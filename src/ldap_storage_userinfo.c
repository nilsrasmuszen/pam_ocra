/*-
* Copyright(c) 2017 Nils Rasmuszen
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
* 1. Redistributions of source code must retain the above copyright
*    notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
*    notice, this list of conditions and the following disclaimer in the
*    documentation and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
* OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
* LIABILITY, OR TORT(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
* OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
* SUCH DAMAGE.
*
*/

#include "include/config.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#include <ldap_storage.h>
#include <ldap_storage_values.h>
#include <ldap_storage_session.h>
#include <ldap_storage_util.h>
#include <ldap_storage_userinfo.h>
#include <storage_util.h>

#define LDAP_SEARCH_MAX_RESULTS 1

/**
 * Release User Info
 *
 * private method that frees the memory allocated for the userinfo.
 *
 * @param info
 * Pointer Pointer to a info structure that has memory allocated by
 * get_user_info that needs to be available over the session.
 *
 */
static void
_release_user_info (ldap_user_info_t ** info)
{
	if (*info == NULL) {
		return;
	}

	if ((*info)->user_dn != NULL) {
		ldap_memfree((void *) (*info)->user_dn);
	}

	free (*info);

	*info = NULL;
	return;
}

/**
 * Get User Info.
 *
 * Get the info of the user to the session->info variable.
 * Connect, execute search, iterate results and fill the user_info structure.
 *
 * @param session
 * Pointer to a bound ldap_session.
 *
 * @param user
 * Name of the user.
 *
 * @return LDAP_STORAGE_SUCCESS when all infos are returned.
 */
int
get_user_info (ldap_session_t * session, const char * user)
{
	char filter[LDAP_FILT_MAXSIZ];
	char escaped_user[LDAP_FILT_MAXSIZ];
	int rc;
	LDAPMessage *res = NULL, *msg;
	ldap_ssd_t *ssd, ssdummy;
	struct timeval timeout;

	rc = connect_anonymously(session);
	if (LDAP_STORAGE_SUCCESS != rc) {
		return rc;
	}

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_SIZELIMIT)
	rc = 1;
	(void) ldap_set_option(session->ld, LDAP_OPT_SIZELIMIT, &rc);
#else
	session->ld->ld_sizelimit = 1;
#endif

	rc = escape_string(user, escaped_user, sizeof(escaped_user));
	if (LDAP_STORAGE_SUCCESS != rc) {
		return rc;
	}

	ssd = session->conf->ssd;
	if (NULL == ssd) {
		ssd = &ssdummy;
		ssd->filter = session->conf->filter;
		ssd->base = session->conf->base;
		ssd->scope = session->conf->scope;
		ssd->next = NULL;
	}
	nxt:
	if (NULL != session->conf->filter && NULL != ssd->filter) {
		/**
		 * Add user to configured filter AND ssd filter.
		 */
		snprintf(filter, sizeof filter, "(&(%s)(%s)(%s=%s))",
		    ssd->filter, session->conf->filter, session->conf->user_attr,
		    escaped_user);
	} else if (ssd->filter != NULL) {
		/**
		 * Add user to ssd filter.
		 */
		snprintf(filter, sizeof filter, "(&(%s)(%s=%s))",
		    ssd->filter, session->conf->user_attr, escaped_user);
	} else if (session->conf->filter != NULL) {
		/**
		 * Add user to configured filter.
		 */
		snprintf(filter, sizeof filter, "(&(%s)(%s=%s))",
		    session->conf->filter, session->conf->user_attr, escaped_user);
	} else {
		/**
		 * Only filter for user in base.
		 */
		snprintf(filter, sizeof filter, "(%s=%s)",
		    session->conf->user_attr, escaped_user);
	}

	timeout.tv_sec = session->conf->timelimit_search;
	timeout.tv_usec = 0;

	rc = ldap_search_ext_s(session->ld, ssd->base, ssd->scope, filter,
	    NULL, 0, session->server_ctrls, session->client_ctrls,
	    &timeout, LDAP_NO_LIMIT, &res);

	if (LDAP_SUCCESS != rc &&
	    LDAP_TIMELIMIT_EXCEEDED != rc && LDAP_SIZELIMIT_EXCEEDED != rc) {
		syslog(LOG_ERR, "pam_ocra: ldap_search_s %s", ldap_err2string(rc));
		return LDAP_STORAGE_USER_UNKNOWN;
	}

	msg = ldap_first_entry(session->ld, res);
	if (NULL == msg) {
		ldap_msgfree(res);
		res = NULL;
		if (ssd->next) {
			ssd = ssd->next;
			goto nxt;
		}
		rc = LDAP_STORAGE_USER_UNKNOWN;
		goto cleanup;
	}

	if (NULL != session->info) {
		_release_user_info(&session->info);
	}

	session->info = (ldap_user_info_t *) calloc(1, sizeof (ldap_user_info_t));
	if (NULL == session->info) {
		rc = LDAP_STORAGE_BUF_ERR;
		goto cleanup;
	}

	rc = get_string_value(session, msg, session->conf->user_attr,
	    &session->info->user_dn);

	session->info->user_dn = ldap_get_dn(session->ld, msg);
	if (NULL == session->info->user_dn) {
		ldap_msgfree(res);
		_release_user_info(&session->info);
		return LDAP_STORAGE_ERROR;
	}

	rc = get_string_value(session, msg, session->conf->key_attr,
	    &session->info->key);
	if (LDAP_STORAGE_ERROR == rc) {
		syslog(LOG_ERR, "pam_orca: Failed to get required 'key' from LDAP");
		goto cleanup;
	}

	rc = get_string_value(session, msg, session->conf->suite_attr,
	    &session->info->suite);
	if (LDAP_STORAGE_ERROR == rc) {
		syslog(LOG_ERR, "pam_orca: Failed to get required 'suite' from LDAP");
		goto cleanup;
	}

	rc = get_string_value(session, msg, session->conf->counter_attr,
	    &session->info->counter);
	if (LDAP_STORAGE_ERROR == rc) {
		session->info->counter = strdup("0");
	}

	rc = get_string_value(session, msg, session->conf->counter_window_attr,
	    &session->info->counter_window);
	if (LDAP_STORAGE_ERROR == rc) {
		session->info->counter_window = strdup("0");
	}

	rc = get_string_value(session, msg, session->conf->pin_hash_attr,
	    &session->info->pin_hash);
	if (LDAP_STORAGE_ERROR == rc) {
		session->info->pin_hash = strdup("");
	}

	rc = get_string_value(session, msg, session->conf->kill_pin_hash_attr,
	    &session->info->kill_pin_hash);
	if (LDAP_STORAGE_ERROR == rc) {
		session->info->kill_pin_hash = strdup("");
	}

	rc = get_string_value(session, msg,
	    session->conf->timestamp_offset_attr,
	    &session->info->timestamp_offset);
	if (LDAP_STORAGE_ERROR == rc) {
		session->info->timestamp_offset = strdup("0");
	}
	rc = LDAP_STORAGE_SUCCESS;

	cleanup:
	if (NULL != res) {
		ldap_msgfree(res);
	}
	return rc;
}


/**
 * Store user info.
 *
 * Store a selection of the infos in the session->info to the directory.
 * Use the config field values as attribute_names and the current values
 * of the session->info structure.
 *
 * @param session
 * Pointer to bound ldap_session.
 */
int
store_user_info (ldap_session_t * session)
{
	int rc;
	rc = set_string_value(session,
	    session->conf->key_attr,
	    session->info->key);
	if (LDAP_STORAGE_ERROR == rc) {
		syslog(LOG_ERR,
		    "pam_ocra: Failed to set required 'key' to LDAP");
		goto cleanup_store_user_info;
	}

	rc = set_string_value(session,
	    session->conf->suite_attr,
	    session->info->suite);
	if (LDAP_STORAGE_ERROR == rc) {
		syslog(LOG_ERR,
		    "pam_ocra: Failed to set required 'suite' to LDAP");
		goto cleanup_store_user_info;
	}

	rc = set_string_value(session,
	    session->conf->counter_attr,
	    session->info->counter);
	if (LDAP_STORAGE_ERROR == rc) {
		syslog(LOG_WARNING,
		    "pam_ocra: Failed to set optional 'counter' to LDAP");
	}

	rc = set_string_value(session,
	    session->conf->counter_window_attr,
	    session->info->counter_window);
	if (LDAP_STORAGE_ERROR == rc) {
		syslog(LOG_WARNING,
		    "pam_ocra: Failed to set optional 'counter_window_attr' to LDAP");
	}

	rc = set_string_value(session,
	    session->conf->pin_hash_attr,
	    session->info->pin_hash);
	if (LDAP_STORAGE_ERROR == rc) {
		syslog(LOG_WARNING,
		    "pam_ocra: Failed to set optional 'pin_hash' to LDAP");
	}

	rc = set_string_value(session,
	    session->conf->kill_pin_hash_attr,
	    session->info->kill_pin_hash);
	if (LDAP_STORAGE_ERROR == rc) {
		syslog(LOG_WARNING,
		    "pam_ocra: Failed to set optional 'kill_pin_hash' to LDAP");
	}

	rc = set_string_value(session,
	    session->conf->timestamp_offset_attr,
	    session->info->timestamp_offset);
	if (LDAP_STORAGE_ERROR == rc) {
		syslog(LOG_WARNING,
		    "pam_ocra: Failed to set optional 'timestamp_offset' to LDAP");
	}
	rc = LDAP_STORAGE_SUCCESS;

	cleanup_store_user_info:
	return rc;
}
