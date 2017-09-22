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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>

#include <ldap_storage.h>
#include <ldap_storage_config.h>

/**
 * Check Buffer
 *
 * Shorthand for checking if the strdup succeeded and if it failed
 * close the file and return a LDAP_STORAGE_BUF_ERROR
 * Beware that there are situations where this macro leads to memory leaks
 * (see ssd)
 *
 * @param str_buffer pointer that should not be NULL.
 * @return
 */
#define CHECK_BUFFER(str_buffer) do { \
		if ((str_buffer) == NULL) { \
			fclose(fp); \
			return LDAP_STORAGE_BUF_ERR; \
		} \
	} while(0)


/**
 * Allocate Config.
 *
 * Allocate the config structure and set default values.
 *
 * @param presult
 * Return pointer to allocate
 *
 * @return LDAP_STORAGE_SUCCESS when allocated.
 */
int
alloc_config(ldap_config_t **presult)
{
	ldap_config_t *result;
	if (NULL == *presult) {
		*presult = (ldap_config_t*) calloc(1, sizeof(*result));
		if (NULL == *presult) {
			return LDAP_STORAGE_BUF_ERR;
		}
	}
	result = *presult;
#ifdef LDAP_VERSION3
	result->version = LDAP_VERSION3;
#else
	result->version = LDAP_VERSION2;
#endif
	result->config_file = NULL;  /* file name read from */
	result->logdir = NULL;  /* directory for debug files */
	result->debug = 0;  /* ldap debug level */
	result->uri = NULL;  /* URI */
	result->base = NULL;  /* base DN, eg. dc=gnu,dc=org */
	result->scope = LDAP_SCOPE_SUBTREE;  /* scope for searches */
	result->deref = LDAP_DEREF_NEVER;  /* deref policy */
	result->bind_dn = NULL;  /* bind dn/pw for "anonymous" authentication */
	result->bind_pw = NULL;
	result->root_bind_dn = NULL;  /* bind dn/pw for "root" authentication */
	result->root_bind_pw = NULL;
	result->filter = NULL;  /* filter to AND with uid=%s */

	result->user_attr = NULL;  /* attribute to search on; defaults to uid. */
	result->key_attr = NULL;  /* attribute for key; defaults to key. */
	result->suite_attr = NULL;  /* attribute for suite; defaults to suite. */
	result->counter_attr = NULL;  /* attribute for counter;
	    defaults to counter. */
	result->counter_window_attr = NULL;  /* attribute for counter_window;
	    defaults to counterWindow. */
	result->pin_hash_attr = NULL;  /* attribute for pin_hash;
	    defaults to pinHash. */
	result->kill_pin_hash_attr = NULL;  /* attribute for kill_pin_hash;
	    defaults to killPinHash. */
	result->timestamp_offset_attr = NULL;  /* attribute for timestamp_offset;
	    defaults to timestampOffset. */

	result->timelimit_bind = 10; /* bind timelimit */
	result->timelimit_search = 10; /* search timelimit */
	result->referrals = 1;  /* automatically lookup referrals */
	result->restart = 1;  /* restart interrupted syscalls, OpenLDAP only */
	result->ssl_on = SSL_OFF;  /* SSL config state */
	result->ssl_path = NULL;  /* SSL path */
	result->ssd = NULL;  /* list of SSDs to augment defaults */
	result->tls_check_peer = -1;  /* tls check peer */
	result->tls_cacert_file = NULL;  /* tls ca certificate file */
	result->tls_cacert_dir = NULL;  /* tls ca certificate dir */
	result->tls_ciphers = NULL;  /* tls ciphersuite */
	result->tls_cert = NULL;  /* tls certificate */
	result->tls_key = NULL;  /* tls key */
	result->tls_rand_file = NULL;  /* tls randfile */
	result->sasl_mechanism = NULL;  /* SASL mechanism */
	return LDAP_STORAGE_SUCCESS;
}


/**
 * Read Config.
 *
 * Read configuration from the config_file to the config structure. Allocates
 * memory, parse the file, ignore comments, trim values, convert and copy
 * them to the internal structure.
 *
 * @param config_file
 * Path to the config file (/etc/ldap.conf)
 *
 * @param presult
 * Return pointer for configuration
 */
int
read_config(const char *config_file, ldap_config_t ** presult)
{
	/* this is the same configuration file as nss_ldap */
	FILE *fp;
	char b[MAX_CONFIG_LINE_SIZE];
	ldap_config_t *result;
	char *k, *v;
	int len;
	char *s;
	ldap_ssd_t *p, *ssd;

	if (LDAP_STORAGE_SUCCESS != alloc_config(presult)) {
		return LDAP_STORAGE_BUF_ERR;
	}

	result = *presult;

	/* configuration file location is configurable; default /etc/ldap.conf */
	if (NULL == config_file) {
		config_file = PAM_LDAP_PATH_CONF;
		result->config_file = NULL;
	} else {
		result->config_file = strdup(config_file);
		if (NULL == result->config_file) {
			return LDAP_STORAGE_BUF_ERR;
		}
	}

	fp = fopen(config_file, "r");

	if (NULL == fp) {
		/*
		 * According to PAM Documentation, such an error in a config file
		 * SHOULD be logged at LOG_ALERT level
		 */
		syslog(LOG_ALERT, "pam_ocra: missing file \"%s\"", config_file);
		return LDAP_STORAGE_ERROR;
	}

	result->scope = LDAP_SCOPE_SUBTREE;

	while (NULL != fgets(b, sizeof(b), fp)) {

		if ('\n' == *b || '#' == *b) {
			continue;
		}

		k = b;
		v = k;
		while ('\0' != *v && ' ' != *v && '\t' != *v) {
			v++;
		}

		if ('\0' == *v) {
			continue;
		}

		*(v++) = '\0';

		/* skip  whitespaces between keyword and value */
		while (' ' == *v || '\t' == *v) {
			v++;
		}

		/* remove whitespaces and newline at the end of value */
		len = strlen(v) - 1;
		while (' ' == v[len] || '\t' == v[len] || '\n' == v[len]) {
			len--;
		}
		v[len + 1] = '\0';

		if (!strcasecmp(k, "uri")) {
			CHECK_BUFFER(result->uri = strdup(v));
		} else if (!strcasecmp(k, "base")) {
			CHECK_BUFFER(result->base = strdup(v));
		} else if (!strcasecmp(k, "bind_dn")) {
			CHECK_BUFFER(result->bind_dn = strdup(v));
		} else if (!strcasecmp(k, "bind_pw")) {
			CHECK_BUFFER(result->bind_pw = strdup(v));
		} else if (!strcasecmp(k, "root_bind_dn")) {
			CHECK_BUFFER(result->root_bind_dn = strdup(v));
		} else if (!strcasecmp(k, "scope")) {
			if (!strncasecmp(v, "sub", 3)) {
				result->scope = LDAP_SCOPE_SUBTREE;
			}
		} else if (!strncasecmp(v, "one", 3)) {
			result->scope = LDAP_SCOPE_ONELEVEL;
		} else if (!strncasecmp(v, "base", 4)) {
			result->scope = LDAP_SCOPE_BASE;
		} else if (!strcasecmp(k, "deref")) {
			if (!strcasecmp(v, "never")) {
				result->deref = LDAP_DEREF_NEVER;
			}
		} else if (!strcasecmp(v, "searching")) {
			result->deref = LDAP_DEREF_SEARCHING;
		} else if (!strcasecmp(v, "finding")) {
			result->deref = LDAP_DEREF_FINDING;
		} else if (!strcasecmp(v, "always")) {
			result->deref = LDAP_DEREF_ALWAYS;
		} else if (!strcasecmp(k, "timelimit_bind")) {
			result->timelimit_bind = atoi(v);
		} else if (!strcasecmp(k, "timelimit_search")) {
			result->timelimit_search = atoi(v);
		} else if (!strcasecmp(k, "nss_base_passwd")) {
			ssd = calloc(1, sizeof (ldap_ssd_t));

			/* this doesn't do any escaping. XXX. */
			s = strchr(v, '?');
			if (NULL != s) {
				len = s - v;
				if (',' == s[-1] && result->base) {
					ssd->base = malloc(len + strlen(result->base) + 1);
					strncpy(ssd->base, v, len);
					strcpy(ssd->base + len, result->base);
				} else {
					ssd->base = malloc(len + 1);
					strncpy(ssd->base, v, len);
					ssd->base[len] = '\0';
				}
				s++;
				if (!strncasecmp(s, "sub", 3)) {
					ssd->scope = LDAP_SCOPE_SUBTREE;
				} else if (!strncasecmp(s, "one", 3)) {
					ssd->scope = LDAP_SCOPE_ONELEVEL;
				} else if (!strncasecmp(s, "base", 4)) {
					ssd->scope = LDAP_SCOPE_BASE;
				}
				s = strchr(s, '?');
				if (NULL != s) {
					s++;
					// cannot use CHECK_BUFFER
					ssd->filter = strdup(s);
					if (NULL == ssd->filter) {
						free(ssd);
						fclose(fp);
						return LDAP_STORAGE_BUF_ERR;
					}
				}
			} else {
				ssd->base = strdup(v);
				ssd->scope = LDAP_SCOPE_SUBTREE;
			}

			for(p = result->ssd; p && p->next; p = p->next);
			if (p) {
				p->next = ssd;
			} else {
				result->ssd = ssd;
			}
		} else if (!strcasecmp(k, "ldap_version")) {
			result->version = atoi(v);
		} else if (!strcasecmp(k, "ssl_path")) {
		  CHECK_BUFFER(result->ssl_path = strdup(v));
		} else if (!strcasecmp(k, "ssl")) {
			if (!strcasecmp(v, "on") || !strcasecmp(v, "yes")
			    || !strcasecmp(v, "true")) {
				result->ssl_on = SSL_LDAPS;
			} else if (!strcasecmp(v, "start_tls")) {
				result->ssl_on = SSL_START_TLS;
			}
		} else if (!strcasecmp(k, "referrals")) {
			result->referrals =(!strcasecmp(v, "on") || !strcasecmp(v, "yes")
			    || !strcasecmp(v, "true"));
		} else if (!strcasecmp(k, "restart")) {
			result->restart =(!strcasecmp(v, "on") || !strcasecmp(v, "yes")
			    || !strcasecmp(v, "true"));
		} else if (!strcasecmp(k, "pam_filter")) {
			CHECK_BUFFER(result->filter = strdup(v));
		} else if (!strcasecmp(k, "pam_login_attribute")) {
			CHECK_BUFFER(result->user_attr = strdup(v));
		} else if (!strcasecmp(k, "pam_key_attribute")) {
			CHECK_BUFFER(result->key_attr = strdup(v));
		} else if (!strcasecmp(k, "pam_suite_attribute")) {
			CHECK_BUFFER(result->suite_attr = strdup(v));
		} else if (!strcasecmp(k, "pam_counter_attribute")) {
			CHECK_BUFFER(result->counter_attr = strdup(v));
		} else if (!strcasecmp(k, "pam_counter_window_attribute")) {
			CHECK_BUFFER(result->counter_window_attr = strdup(v));
		} else if (!strcasecmp(k, "pam_pin_hash_attribute")) {
			CHECK_BUFFER(result->pin_hash_attr = strdup(v));
		} else if (!strcasecmp(k, "pam_kill_pin_hash_attribute")) {
			CHECK_BUFFER(result->kill_pin_hash_attr = strdup(v));
		} else if (!strcasecmp(k, "pam_timestamp_offset_attribute")) {
			CHECK_BUFFER(result->timestamp_offset_attr = strdup(v));
		} else if (!strcasecmp(k, "tls_check_peer")) {
			if (!strcasecmp(v, "on") || !strcasecmp(v, "yes")
			    || !strcasecmp(v, "true")) {
				result->tls_check_peer = 1;    /* LDAP_OPT_X_TLS_HARD */
			} else if (!strcasecmp(v, "off") || !strcasecmp(v, "no")
			    || !strcasecmp(v, "false")) {
				result->tls_check_peer = 0;    /* LDAP_OPT_X_TLS_NEVER */
			}
		} else if (!strcasecmp(k, "tls_cacert_file")) {
			CHECK_BUFFER(result->tls_cacert_file = strdup(v));
		} else if (!strcasecmp(k, "tls_cacert_dir")) {
			CHECK_BUFFER(result->tls_cacert_dir = strdup(v));
		} else if (!strcasecmp(k, "tls_ciphers")) {
			CHECK_BUFFER(result->tls_ciphers = strdup(v));
		} else if (!strcasecmp(k, "tls_cert")) {
			CHECK_BUFFER(result->tls_cert = strdup(v));
		} else if (!strcasecmp(k, "tls_key")) {
			CHECK_BUFFER(result->tls_key = strdup(v));
		} else if (!strcasecmp(k, "tls_rand_file")) {
			CHECK_BUFFER(result->tls_rand_file = strdup(v));
		} else if (!strcasecmp(k, "logdir")) {
			CHECK_BUFFER(result->logdir = strdup(v));
		} else if (!strcasecmp(k, "pam_sasl_mech")) {
			CHECK_BUFFER(result->sasl_mechanism = strdup(v));
		} else if (!strcasecmp(k, "debug")) {
			result->debug = atol(v);
		}
	}

	if (NULL == result->uri) {
		/*
		 * According to PAM Documentation, such an error in a config file
		 * SHOULD be logged at LOG_ALERT level
		 */
		syslog(LOG_ALERT, "pam_ocra: missing \"uri\" in file \"%s\"",
		    config_file);
		return LDAP_STORAGE_ERROR;
	}

#if !(defined(HAVE_SASL_SASL_H) || defined(HAVE_SASL_H)) && !defined(HAVE_LDAP_SASL_INTERACTIVE_BIND_S)
	if (result->sasl_mechanism != NULL) {
		syslog(LOG_ERR, "pam_ocra: SASL mechanism \"%s\" requested, "
		    "but module not built with SASL support", result->sasl_mechanism);
		return LDAP_STORAGE_ERROR;
	}
#endif
	/**
	 * Defaults
	 */

	if (NULL == result->user_attr) {
		CHECK_BUFFER(result->user_attr = strdup("uid"));
	}
	if (NULL == result->key_attr) {
		CHECK_BUFFER(result->key_attr = strdup("key"));
	}
	if (NULL == result->suite_attr) {
		CHECK_BUFFER(result->suite_attr = strdup("suite"));
	}
	if (NULL == result->counter_attr) {
		CHECK_BUFFER(result->counter_attr = strdup("counter"));
	}
	if (NULL == result->counter_window_attr) {
		CHECK_BUFFER(result->counter_window_attr = strdup("counterWindow"));
	}
	if (NULL == result->pin_hash_attr) {
		CHECK_BUFFER(result->pin_hash_attr = strdup("pinHash"));
	}
	if (NULL == result->kill_pin_hash_attr) {
		CHECK_BUFFER(result->kill_pin_hash_attr = strdup("killPinHash"));
	}
	if (NULL == result->timestamp_offset_attr) {
		CHECK_BUFFER(result->timestamp_offset_attr = strdup("timestampOffset"));
	}

	fclose(fp);

	if ((NULL != result->root_bind_dn) && (0 == geteuid())) {
		/**
		 * Read root password from secret file
		 */
		fp = fopen(PAM_LDAP_PATH_ROOTPASSWD, "r");
		if (NULL == fp) {
			if (NULL != fgets(b, sizeof (b), fp)) {
				int len;
				len = strlen(b);
				if (len > 0 && '\n' == b[len - 1]) {
					len--;
				}
				b[len] = '\0';
				result->root_bind_pw = strdup(b);
			}
			fclose(fp);
		} else {
			syslog(LOG_WARNING,
			    "pam_ocra: could not open secret file %s(%s)",
			PAM_LDAP_PATH_ROOTPASSWD, strerror(errno));
		}
	}

	memset(b, 0, MAX_CONFIG_LINE_SIZE);
	return LDAP_STORAGE_SUCCESS;
}


/**
 * Release Config.
 *
 * Release allocated config values.
 *
 * @param pconfig
 * Return Pointer to free
 */
void
release_config(ldap_config_t ** pconfig)
{
	ldap_config_t *c;

	c = *pconfig;
	if (NULL == c) {
		return;
	}

	if (NULL != c->config_file) {
		free(c->config_file);
	}
	if (NULL != c->logdir) {
		free(c->logdir);
	}

	if (NULL != c->uri) {
		free(c->uri);
	}
	if (NULL != c->base) {
		free(c->base);
	}

	if (NULL != c->bind_dn) {
		free(c->bind_dn);
	}
	if (NULL != c->bind_pw) {
		free(c->bind_pw);
	}

	if (NULL != c->root_bind_dn) {
		free(c->root_bind_dn);
	}
	if (NULL != c->root_bind_pw) {
		free(c->root_bind_pw);
	}
	if (NULL != c->filter) {
		free(c->filter);
	}

	if (NULL != c->user_attr) {
		free(c->user_attr);
	}
	if (NULL != c->key_attr) {
		free(c->key_attr);
	}
	if (NULL != c->suite_attr) {
		free(c->suite_attr);
	}
	if (NULL != c->counter_attr) {
		free(c->counter_attr);
	}
	if (NULL != c->counter_window_attr) {
		free(c->counter_window_attr);
	}
	if (NULL != c->pin_hash_attr) {
		free(c->pin_hash_attr);
	}
	if (NULL != c->kill_pin_hash_attr) {
		free(c->kill_pin_hash_attr);
	}
	if (NULL != c->timestamp_offset_attr) {
		free(c->timestamp_offset_attr);
	}

	if (NULL != c->ssl_path) {
		free(c->ssl_path);
	}
	if (NULL != c->ssd) {
		free(c->ssd);
	}

	if (NULL != c->tls_cacert_file) {
		free(c->tls_cacert_file);
	}
	if (NULL != c->tls_cacert_dir) {
		free(c->tls_cacert_dir);
	}
	if (NULL != c->tls_ciphers) {
		free(c->tls_ciphers);
	}
	if (NULL != c->tls_cert) {
		free(c->tls_cert);
	}
	if (NULL != c->tls_key) {
		free(c->tls_key);
	}
	if (NULL != c->tls_rand_file) {
		free(c->tls_rand_file);
	}
	if (NULL != c->sasl_mechanism) {
		free(c->sasl_mechanism);
	}

	memset(c, 0, sizeof (*c));
	free(c);
	*pconfig = NULL;

	return;
}
