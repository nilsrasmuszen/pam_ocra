/*-
 * Copyright (c) 2017 Nils Rasmuszen
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
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */
#pragma once
#include "include/config.h"

#if defined(HAVE_CRYPT_H)
#include <crypt.h>
#elif defined(HAVE_DES_H)
#include <des.h>
#endif

#ifdef HAVE_LBER_H
#include <lber.h>
#endif
#ifdef HAVE_LDAP_H
#include <sys/types.h>
#include <ldap.h>
#endif
#ifdef HAVE_LDAP_SSL_H
#include <ldap_ssl.h>
#endif
#ifdef HAVE_SASL_SASL_H
#include <sasl/sasl.h>
#elif defined(HAVE_SASL_H)
#include <sasl.h>
#endif

/* SSL config states */
#define SSL_OFF 0
#define SSL_LDAPS 1
#define SSL_START_TLS 2

/* chauthtok config states */
#define PASSWORD_CLEAR 0
#define PASSWORD_CRYPT 1
#define PASSWORD_MD5 2
#define PASSWORD_CLEAR_REMOVE_OLD 3
#define PASSWORD_AD 4
#define PASSWORD_EXOP 5
#define PASSWORD_EXOP_SEND_OLD 6


#ifndef LDAP_OPT_ON
#define LDAP_OPT_ON ((void *) 1)
#endif
#ifndef LDAP_OPT_OFF
#define LDAP_OPT_OFF ((void *) 0)
#endif
#ifndef LDAP_FILT_MAXSIZ
#define LDAP_FILT_MAXSIZ 1024
#endif /* LDAP_FILT_MAXSIZ */

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE !FALSE
#endif

/* ldap_storage interface return values */
#define LDAP_STORAGE_SUCCESS 0
#define LDAP_STORAGE_ERROR 1
#define LDAP_STORAGE_BUF_ERR 2
#define LDAP_STORAGE_USER_UNKNOWN 3
#define LDAP_STORAGE_NOT_AVAILABLE 4
#define LDAP_STORAGE_ERROR_CRED_INVALID 5

#define MAX_CONFIG_LINE_SIZE 4096


typedef struct ldap_ssd {
	char *base;
	int scope;
	char *filter;
	struct ldap_ssd *next;
} ldap_ssd_t;

/* /etc/ldap.conf nss_ldap-style configuration */
typedef struct ldap_config {
	int version;  /* LDAP protocol version */
	char *config_file;  /* file name read from */
	char *logdir;  /* directory for debug files */
	int debug;  /* ldap debug level */

	char *uri;  /* URI */
	char *base;  /* base DN, eg. dc=gnu,dc=org */
	int scope;  /* scope for searches */
	int deref;  /* deref policy */

	char *bind_dn;  /* bind dn/pw for "anonymous" authentication */
	char *bind_pw;
	char *root_bind_dn;  /* bind dn/pw for "root" authentication */
	char *root_bind_pw;
	char *filter;  /* filter to AND with uid=%s */

	/* attributes to request and process */
	char *user_attr;
	char *key_attr;
	char *suite_attr;
	char *counter_attr;
	char *counter_window_attr;
	char *pin_hash_attr;
	char *kill_pin_hash_attr;
	char *timestamp_offset_attr;

	int timelimit_bind; /* bind timelimit */
	int timelimit_search; /* search timelimit */
	int referrals;  /* automatically lookup referrals */
	int restart;  /* restart interrupted syscalls, OpenLDAP only */

	uid_t min_uid;  /* min uid */
	uid_t max_uid;  /* max uid */

	int ssl_on;  /* SSL config state */
	char *ssl_path;  /* SSL path */
	ldap_ssd_t *ssd;  /* list of SSDs to augment defaults */
	int tls_check_peer;  /* tls check peer */

	char *tls_cacert_file;  /* tls ca certificate file */
	char *tls_cacert_dir;  /* tls ca certificate dir */
	char *tls_ciphers;  /* tls ciphersuite */
	char *tls_cert;  /* tls certificate */
	char *tls_key;  /* tls key */
	char *tls_rand_file;  /* tls randfile */
	char *sasl_mechanism;  /* SASL mechanism */
} ldap_config_t;

/**
 * Userinfo.
 * matches res/etc/openldap/pam-ocra.schema
 */
typedef struct ldap_user_info {
	char *user_dn;  /* DN of user in directory */
	char *uid;  /* uid */
	char *key;  /* ocra key */
	char *suite;  /* suite */
	char *counter;  /* counter */
	char *counter_window;  /* counter window */
	char *pin_hash;  /* pin hash */
	char *kill_pin_hash;  /* kill pin hash */
	char *timestamp_offset;  /* ocra timestamp offset */
} ldap_user_info_t;

/*
 * LDAP session. To minmize binds and searches to the directory.
 * A v2 session cannot rebind.
 */
typedef struct ldap_session {
	LDAP *ld;
	ldap_config_t *conf;
	ldap_user_info_t *info;
	LDAPControl **server_ctrls;
	LDAPControl **client_ctrls;
} ldap_session_t;
