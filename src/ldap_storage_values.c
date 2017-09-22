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

#include <pwd.h>
#include <stdlib.h>
#include <syslog.h>

#include <ldap_storage.h>
#include <ldap_storage_values.h>


/**
 * Get String Value.
 *
 * Get a string from the given ldap message that has to contain the attribute.
 *
 * @param session
 * Pointer to a session that is bound and connected.
 *
 * @param ldap_message
 * Pointer to a LDAPMessage that was returned by ldap_search_ext
 *
 * @param attribute
 * Name of the attribute that is to be returned.
 *
 * @param output
 * Pointer to a string where the value is returned. The memory for output has
 * to be freed by the caller.
 *
 * @return LDAP_STORAGE_SUCCESS when the value was copied correctly.
 */
int
get_string_value (ldap_session_t * session, LDAPMessage * ldap_message,
    const char * attribute, char ** output)
{
	struct berval **values;
	int rc;

	values = ldap_get_values_len(session->ld, ldap_message,
	    (char *) attribute);
	if (NULL == values) {
		/**
		 * Do not output a log message, callee will decide on error
		 * if this is relevant for the log.
		 */
		return LDAP_STORAGE_ERROR;
	}
	*output = malloc(values[0]->bv_len + 1);
	strncpy(*output, values[0]->bv_val, values[0]->bv_len + 1);
	if (NULL == *output) {
		syslog(LOG_ERR, "pam_ocra: Unable to copy value to output buffer.");
		rc = LDAP_STORAGE_BUF_ERR;
	} else {
		rc = LDAP_STORAGE_SUCCESS;
	}

	ldap_value_free_len(values);

	return rc;
}


/**
 * Set String Value.
 *
 * Set a string value to the attribute in the current user_dn. When
 * the value is "", the attribute is removed.
 *
 * @param session
 * Pointer to a session that is bound and connected.
 *
 * @param attribute
 * Name of the attribute to modify or remove.
 *
 * @param value
 * New value of the attribute.
 *
 * @return LDAP_STORAGE_SUCCESS when the directory accepted the change.
 */
int
set_string_value (ldap_session_t * session,
    const char * attribute,
    const char * value)
{
	struct ldapmod mod;
	struct ldapmod *mods[2];
	char * mod_value[2];
	int rc;
	mod.mod_type = strdup(attribute);
	if (0 == strcmp(value, "")) {
		mod.mod_op = LDAP_MOD_DELETE;
		mod_value[0] = NULL;
		mod_value[1] = NULL;
	} else {
		mod.mod_op = LDAP_MOD_REPLACE;
		mod_value[0] = strdup(value);
		mod_value[1] = NULL;
	}
	mod.mod_values = mod_value;
	mods[0] = &mod;
	mods[1] = NULL;

	rc = ldap_modify_ext_s(session->ld, session->info->user_dn, mods,
	    session->server_ctrls, session->client_ctrls);

	if (LDAP_SUCCESS != rc && LDAP_MOD_DELETE != mod.mod_op) {
		syslog(LOG_ERR, "pam_ocra: ldap_modify_ext_s %s",
		    ldap_err2string(rc));
		rc = LDAP_STORAGE_ERROR;
	} else {
		rc = LDAP_STORAGE_SUCCESS;
	}

	return rc;
}
