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

#include <sys/types.h>
#include <unistd.h>
#include <syslog.h>

#include <ldap_storage.h>
#include <ldap_storage_rebind.h>
#include <ldap_storage_util.h>


/**
 * Rebind Proc
 *
 * Callback method for rebind. It implements that rebind for different
 * ldap api's.
 * Returns the session configuration urls, credentials etc
 * in the right format to the api.
 *
 * @param ld
 * LDAP pointer
 *
 * @param others
 * depend on the api, see documentation.
 *
 * @return LDAP_SUCCESS when rebind succeed.
 */
int
rebind_proc(LDAP * ld,
#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)
#if LDAP_SET_REBIND_PROC_ARGS == 3
    LDAP_CONST char *url, ber_tag_t request, ber_int_t msgid, void *arg
#else /* LDAP_SET_REBIND_PROC_ARGS == 3 */
    LDAP_CONST char *url, int request, ber_int_t msgid
#endif /* else LDAP_SET_REBIND_PROC_ARGS == 3 */
#else /* (LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000) */
#if LDAP_SET_REBIND_PROC_ARGS == 3
    char **whop, char **credp, int *methodp, int freeit, void *arg
#else /* LDAP_SET_REBIND_PROC_ARGS == 3 */
    char **whop, char **credp, int *methodp, int freeit
#endif /* else LDAP_SET_REBIND_PROC_ARGS == 3 */
#endif /* else (LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000) */
)
{
	int rc = LDAP_SUCCESS;

#if LDAP_SET_REBIND_PROC_ARGS == 3
	ldap_session_t *session = (ldap_session_t *) arg;
#else
	/* ugly hack */
	ldap_session_t *session = global_session;
#endif

#if defined(LDAP_API_FEATURE_X_OPENLDAP) &&(LDAP_API_VERSION > 2000)
	char *who, *cred;
	struct timeval timeout;
#if defined(HAVE_LDAP_PARSE_RESULT) && defined(HAVE_LDAP_CONTROLS_FREE)
	LDAPMessage *result;
	LDAPControl **psrvctrls = NULL;
	struct berval userpw;
#endif /* HAVE_LDAP_PARSE_RESULT && HAVE_LDAP_CONTROLS_FREE */

	if (session->conf->root_bind_dn != NULL && geteuid() == 0) {
		who = session->conf->root_bind_dn;
		cred = session->conf->root_bind_pw;
	} else {
		who = session->conf->bind_dn;
		cred = session->conf->bind_pw;
	}

	if (session->conf->ssl_on == SSL_START_TLS) {
		rc = ldap_start_tls_s(session->ld, NULL, NULL);
		if (rc != LDAP_SUCCESS) {
			syslog(LOG_ERR, "pam_ocra: ldap_starttls_s: %s",
				ldap_err2string(rc));
			return LDAP_OPERATIONS_ERROR;
		}
	}

	userpw.bv_val = cred;
	userpw.bv_len = (userpw.bv_val != 0) ? strlen(userpw.bv_val) : 0;

	rc = ldap_sasl_bind(session->ld, who, LDAP_SASL_SIMPLE,
		&userpw, psrvctrls, 0, &msgid);
	if (rc != LDAP_SUCCESS ) {
		return rc;
	}

	if (msgid == -1) {
		syslog(LOG_ERR, "pam_ocra: ldap_sasl_bind %s",
		    ldap_err2string(ldap_get_lderrno(ld, 0, 0)));
		return LDAP_OPERATIONS_ERROR;
	}

	timeout.tv_sec = session->conf->timelimit_bind;
	timeout.tv_usec = 0;
	result = NULL;
	rc = ldap_result(ld, msgid, FALSE, &timeout, &result);
	if (-1 == rc || 0 == rc) {
		syslog(LOG_ERR, "pam_ocra: ldap_result %s",
		    ldap_err2string(ldap_get_lderrno(ld, 0, 0)));
		ldap_msgfree(result);
		return LDAP_OPERATIONS_ERROR;
	}

#else /* defined(LDAP_API_FEATURE_X_OPENLDAP) &&(LDAP_API_VERSION > 2000) */


	if (freeit) {
		// XXX_pam_drop(*whop);
		// XXX_pam_overwrite(*credp);
		// XXX_pam_drop(*credp);
		return LDAP_SUCCESS;
	}

	if (session->conf->root_bind_dn != NULL && geteuid() == 0) {
		*whop = strdup(session->conf->root_bind_dn);
		*credp = session->conf->root_bind_pw != NULL ?
		strdup(session->conf->root_bind_pw) : NULL;
	} else {
		*whop = session->conf->bind_dn != NULL ?
		strdup(session->conf->bind_dn) : NULL;
		*credp = session->conf->bind_pw != NULL ?
		strdup(session->conf->bind_pw) : NULL;
	}

	*methodp = LDAP_AUTH_SIMPLE;

#endif
	return rc;
}
