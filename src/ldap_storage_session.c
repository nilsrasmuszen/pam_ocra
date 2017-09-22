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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>

#include <ldap_storage.h>
#include <ldap_storage_rebind.h>
#include <ldap_storage_config.h>
#include <ldap_storage_session.h>
#include <ldap_storage_util.h>

#ifdef LBER_OPT_LOG_PRINT_FILE
static FILE *debugfile = NULL;
#endif

/* TLS routines */
#if defined HAVE_LDAP_START_TLS_S \
    || (defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_X_TLS))

/**
 * Set SSL Default Options.
 *
 * Set default SSL options for the session. These options include, depending
 * on the system, a TLS_RANDOM_FILE, TLS_CACERT_FILE, TLS_REQUIRE_CERT,
 * TLS_CIPHER_SUITE, TLS_CERTFILE and TLS_KEYFILE from the values
 * of the ldap.conf
 *
 * @param session
 * Pointer to bound session.
 *
 * @return LDAP_STORAGE_SUCCESS when all options could be set.
 */
/* Some global TLS-specific options need to be set before we create our
 * session context, so we set them here. */
static int
_set_ssl_default_options(ldap_session_t * session)
{
	int rc;

#ifdef LDAP_OPT_X_TLS_RANDOM_FILE
	/* rand file */
	if (session->conf->tls_rand_file != NULL) {
		rc = ldap_set_option(NULL, LDAP_OPT_X_TLS_RANDOM_FILE,
		    session->conf->tls_rand_file);
		if (rc != LDAP_SUCCESS) {
			syslog(LOG_ERR,
			    "pam_ocra: ldap_set_option(LDAP_OPT_X_TLS_RANDOM_FILE): %s",
			    ldap_err2string(rc));
			return LDAP_OPERATIONS_ERROR;
		}
	}
#endif /* LDAP_OPT_X_TLS_RANDOM_FILE */

	/* ca cert file */
	if (session->conf->tls_cacert_file != NULL) {
		rc = ldap_set_option(NULL, LDAP_OPT_X_TLS_CACERTFILE,
		    session->conf->tls_cacert_file);
		if (rc != LDAP_SUCCESS) {
			syslog(LOG_ERR,
			    "pam_ocra: ldap_set_option(LDAP_OPT_X_TLS_CACERTFILE): %s",
			    ldap_err2string(rc));
			return LDAP_OPERATIONS_ERROR;
		}
	}

	if (session->conf->tls_cacert_dir != NULL) {
		/* ca cert directory */
		rc = ldap_set_option(NULL, LDAP_OPT_X_TLS_CACERTDIR,
		    session->conf->tls_cacert_dir);
		if (rc != LDAP_SUCCESS) {
			syslog(LOG_ERR,
			    "pam_ocra: ldap_set_option(LDAP_OPT_X_TLS_CACERTDIR): %s",
			    ldap_err2string(rc));
			return LDAP_OPERATIONS_ERROR;
		}
	}

	if (session->conf->tls_check_peer > -1) {
		/* require cert? */
		rc = ldap_set_option(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT,
		    &session->conf->tls_check_peer);
		if (rc != LDAP_SUCCESS) {
			syslog(LOG_ERR,
			    "pam_ocra: ldap_set_option(LDAP_OPT_X_TLS_REQUIRE_CERT): %s",
			    ldap_err2string(rc));
			return LDAP_OPERATIONS_ERROR;
		}
	}

	if (session->conf->tls_ciphers != NULL) {
		/* set cipher suite, certificate and private key: */
		rc = ldap_set_option(NULL, LDAP_OPT_X_TLS_CIPHER_SUITE,
		    session->conf->tls_ciphers);
		if (rc != LDAP_SUCCESS) {
			syslog(LOG_ERR,
			    "pam_ocra: ldap_set_option(LDAP_OPT_X_TLS_CIPHER_SUITE): %s",
			    ldap_err2string(rc));
			return LDAP_OPERATIONS_ERROR;
		}
	}

	if (session->conf->tls_cert != NULL) {
		rc = ldap_set_option(NULL, LDAP_OPT_X_TLS_CERTFILE,
		    session->conf->tls_cert);
		if (rc != LDAP_SUCCESS) {
			syslog(LOG_ERR,
			    "pam_ocra: ldap_set_option(LDAP_OPT_X_TLS_CERTFILE): %s",
			    ldap_err2string(rc));
			return LDAP_OPERATIONS_ERROR;
		}
	}

	if (session->conf->tls_key != NULL) {
		rc = ldap_set_option(NULL, LDAP_OPT_X_TLS_KEYFILE,
		    session->conf->tls_key);
		if (rc != LDAP_SUCCESS) {
			syslog(LOG_ERR,
			    "pam_ocra: ldap_set_option(LDAP_OPT_X_TLS_KEYFILE): %s",
			    ldap_err2string(rc));
			return LDAP_OPERATIONS_ERROR;
		}
	}

	return LDAP_SUCCESS;
}
#endif /* TLS routines */


/**
 * Get Session.
 *
 * Alloctate the session structure, Read the configuration and initialize
 * structure members.
 *
 * @param config_file
 * Path to a configuration file (/etc/ldap.conf)
 *
 * @param psession
 * Return pointer to ldap_session
 *
 * @return LDAP_STORAGE_SUCCESS when the structure is initialized.
 */
int
get_session(const char * config_file,
	ldap_session_t ** psession)
{
	ldap_session_t *session;
	int rc;

	*psession = NULL;
	session = (ldap_session_t *) calloc(1, sizeof(*session));
#if LDAP_SET_REBIND_PROC_ARGS < 3
	global_session = session;
#endif
	if (NULL == session) {
		return LDAP_STORAGE_BUF_ERR;
	}

	session->ld = NULL;
	session->conf = NULL;
	session->info = NULL;
	session->server_ctrls = NULL;
	session->client_ctrls = NULL;

	rc = read_config(config_file, &session->conf);

	if (LDAP_SUCCESS != rc) {
		release_config(&session->conf);
		free(session->conf);
		free(session);
		return rc;
	}

	*psession = session;

	return LDAP_STORAGE_SUCCESS;
}


/**
 * Session Open.
 *
 * Open the session with the values from the configuration.
 * Depending on the system configuration, a debug file is created and the
 * ssl context is setup.
 *
 * @param session
 * Initialized session structure.
 *
 * @return LDAP_STORAGE_SUCCESS when all operations succeeded.
 */
int
session_open(ldap_session_t * session)
{
	int rc;
#ifdef LDAP_X_OPT_CONNECT_TIMEOUT
	int timeout;
#endif
#ifdef LDAP_OPT_NETWORK_TIMEOUT
	struct timeval tv;
#endif

#ifdef HAVE_LDAP_SET_OPTION
	if (session->conf->debug) {
#ifdef LBER_OPT_LOG_PRINT_FILE
		if (session->conf->logdir && !debugfile) {
			char *name = malloc(strlen(session->conf->logdir) + 18);
			if (name) {
				sprintf(name, "%s/ldap.%d", session->conf->logdir,
					(int) getpid());
				debugfile = fopen(name, "a");
				free(name);
			}
			if (debugfile) {
				ber_set_option(NULL, LBER_OPT_LOG_PRINT_FILE, debugfile);
			}
		}
#endif /* LBER_OPT_LOG_PRINT_FILE */
#ifdef LBER_OPT_DEBUG_LEVEL
		ber_set_option(NULL, LBER_OPT_DEBUG_LEVEL, &session->conf->debug);
#endif /* LBER_OPT_DEBUG_LEVEL */

#ifdef LDAP_OPT_DEBUG_LEVEL
		ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, &session->conf->debug);
#endif /* LDAP_OPT_DEBUG_LEVEL */
	}
#endif /* HAVE_LDAP_SET_OPTION */

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_X_TLS)
	/* set defaults for global TLS-related options */
	rc = _set_ssl_default_options(session);
	if (LDAP_SUCCESS != rc) {
		syslog(LOG_ERR,
		    "pam_ocra: _set_ssl_default_options  for ldap failed");
		return rc;
	}
#endif

	if (NULL == session->conf->uri) {
		syslog(LOG_ERR,
		    "pam_ocra: ldap_initialize: no uri defined in config.");
		return LDAP_STORAGE_ERROR;
	}

	rc = ldap_initialize(&session->ld, session->conf->uri);
	if (LDAP_SUCCESS != rc) {
		syslog(LOG_ERR, "pam_ocra: ldap_initialize %s",
		    ldap_err2string(rc));
		return LDAP_STORAGE_ERROR;
	}

	if (NULL == session->ld) {
		syslog(LOG_ERR, "pam_ocra: unable to acquire ldap_session.");
		return LDAP_STORAGE_ERROR;
	}

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_X_TLS)
	if (SSL_LDAPS == session->conf->ssl_on) {
		int tls = LDAP_OPT_X_TLS_HARD;
		rc = ldap_set_option(session->ld, LDAP_OPT_X_TLS, &tls);
		if (LDAP_SUCCESS != rc) {
			syslog(LOG_ERR, "pam_ocra: ldap_set_option(LDAP_OPT_X_TLS) %s",
			    ldap_err2string(rc));
			return LDAP_STORAGE_ERROR;
		}
	}
#endif /* LDAP_OPT_X_TLS */

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_PROTOCOL_VERSION)
	(void) ldap_set_option(session->ld, LDAP_OPT_PROTOCOL_VERSION,
	    &session->conf->version);
#else
	session->ld->ld_version = session->conf->version;
#endif

#if LDAP_SET_REBIND_PROC_ARGS == 3
	ldap_set_rebind_proc(session->ld, rebind_proc,(void *) session);
#elif LDAP_SET_REBIND_PROC_ARGS == 2
	ldap_set_rebind_proc(session->ld, rebind_proc);
#endif

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_DEREF)
	(void) ldap_set_option(session->ld, LDAP_OPT_DEREF, &session->conf->deref);
#else
	session->ld->ld_deref = session->conf->deref;
#endif

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_TIMELIMIT)
	(void) ldap_set_option(session->ld, LDAP_OPT_TIMELIMIT,
		&session->conf->timelimit_search);
#else
	// XXX was LDAP_NO_LIMIT by default
	session->ld->ld_timelimit = session->conf->timelimit_search;
#endif


#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_X_OPT_CONNECT_TIMEOUT)
	timeout = session->conf->timelimit_bind * 1000;
	(void) ldap_set_option(session->ld, LDAP_X_OPT_CONNECT_TIMEOUT, &timeout);
#endif

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_NETWORK_TIMEOUT)
	tv.tv_sec = session->conf->timelimit_bind;
	tv.tv_usec = 0;
	(void) ldap_set_option(session->ld, LDAP_OPT_NETWORK_TIMEOUT, &tv);
#endif

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_REFERRALS)
	(void) ldap_set_option(session->ld, LDAP_OPT_REFERRALS,
	    session->conf->referrals ? LDAP_OPT_ON : LDAP_OPT_OFF);
#endif

#if defined(HAVE_LDAP_SET_OPTION) && defined(LDAP_OPT_RESTART)
	(void) ldap_set_option(session->ld, LDAP_OPT_RESTART,
	    session->conf->restart ? LDAP_OPT_ON : LDAP_OPT_OFF);
#endif

#ifdef HAVE_LDAP_START_TLS_S
	if (SSL_START_TLS == session->conf->ssl_on) {
		int version;
		rc = ldap_get_option(session->ld, LDAP_OPT_PROTOCOL_VERSION, &version);
		if (LDAP_SUCCESS == rc) {
			if (version < LDAP_VERSION3) {
				version = LDAP_VERSION3;
				(void) ldap_set_option(session->ld, LDAP_OPT_PROTOCOL_VERSION,
				    &version);
			}

			rc = ldap_start_tls_s(session->ld, NULL, NULL);
			if (LDAP_SUCCESS != rc) {
				syslog(LOG_ERR, "pam_ocra: ldap_start_tls_s: %s",
				    ldap_err2string(rc));
				return LDAP_STORAGE_ERROR;
			}
		}
	}
#endif /* HAVE_LDAP_START_TLS_S */
	return LDAP_STORAGE_SUCCESS;
}

/**
 * Connect Anonymously.
 *
 * Connect to the session with the configured credentials. When the server
 * does not respond, retry once.
 * After this operation searches and modifications may be executed on the
 * directory.
 * The session structure is then bound and connected.
 *
 * @param session
 * Open session structure.
 *
 * @return LDAP_STORAGE_SUCCESS when all operations succeded.
 */
int
connect_anonymously(ldap_session_t * session)
{
	int rc;
	int msgid;
	struct timeval timeout;
	LDAPMessage *result;
	int reconnect = 0;

	retry:
	if (reconnect) {
		if (NULL != session->ld) {
			ldap_unbind_ext(session->ld,
			    session->client_ctrls, session->server_ctrls);
			session->ld = NULL;
		}
		syslog(LOG_ERR, "pam_ocra: reconnecting to LDAP server...");
	}
	if (NULL == session->ld) {
		rc = session_open(session);
		if (LDAP_STORAGE_SUCCESS != rc) {
			return rc;
		}
	}

	if (session->conf->root_bind_dn && 0 == geteuid()) {
		/**
		 * As root when root_bind_dn was configured
		 */
		struct berval cred;
		cred.bv_val = ber_strdup(session->conf->root_bind_pw);
		cred.bv_len = strlen(cred.bv_val);
		ldap_sasl_bind(session->ld,
		    session->conf->root_bind_dn,
		    LDAP_SASL_SIMPLE,
		    &cred,
		    session->server_ctrls, session->client_ctrls,
		    &msgid);
	} else {
		/**
		 * As any user with bind_pw/bind_dn.
		 */
		struct berval cred;
		cred.bv_val = ber_strdup(session->conf->bind_pw);
		cred.bv_len = strlen(cred.bv_val);
		ldap_sasl_bind(session->ld,
		    ber_strdup(session->conf->bind_dn),
		    LDAP_SASL_SIMPLE,
		    &cred,
		    NULL, NULL,
		    &msgid);
	}

	if (-1 == msgid) {
		int ld_errno = ldap_get_lderrno(session->ld, 0, 0);

		syslog(LOG_ERR, "pam_ocra: ldap_simple_bind %s",
		    ldap_err2string(ld_errno));
		if (LDAP_SERVER_DOWN == ld_errno && !reconnect) {
			reconnect = 1;
			goto retry;
		}
		return LDAP_STORAGE_NOT_AVAILABLE;
	}

	timeout.tv_sec = session->conf->timelimit_bind;   /* default 10 */
	timeout.tv_usec = 0;
	rc = ldap_result(session->ld, msgid, FALSE, &timeout, &result);
	if (-1 == rc || 0 == rc) {
		int ld_errno = ldap_get_lderrno(session->ld, 0, 0);

		syslog(LOG_ERR, "pam_ocra: ldap_result %s",
		    ldap_err2string(ld_errno));
		if (LDAP_SERVER_DOWN == ld_errno && !reconnect) {
			reconnect = 1;
			goto retry;
		}
		return LDAP_STORAGE_NOT_AVAILABLE;
	}

#ifdef HAVE_LDAP_PARSE_RESULT
	ldap_parse_result(session->ld, result, &rc, 0, 0, 0, 0, TRUE);
#else
	rc = ldap_result2error(session->ld, result, TRUE);
#endif

	if (LDAP_SUCCESS != rc) {
		syslog(LOG_ERR, "pam_ocra: error trying to bind (%s)",
		    ldap_err2string(rc));
		return LDAP_STORAGE_ERROR_CRED_INVALID;
	}

	return LDAP_STORAGE_SUCCESS;
}
