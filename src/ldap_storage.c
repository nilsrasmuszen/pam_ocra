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

#include "include/config.h"

#include <pwd.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <errno.h>

#include <storage_util.h>
#include <ldap_storage.h>
#include <ldap_storage_config.h>
#include <ldap_storage_rebind.h>
#include <ldap_storage_session.h>
#include <ldap_storage_userinfo.h>
#include <ldap_storage_values.h>
#include <ldap_storage_util.h>

/*
 * dummy, pam session closes in db_open
 */
int
config_db_close(DB * db){
	int r = LDAP_STORAGE_SUCCESS;

	return r;
}


int
get_key_from_string(const char * string_value, char ** V, size_t * V_l)
{
	uint8_t *key;
	if (strlen(string_value) % 2 != 0) {
		syslog(LOG_ERR, "Invalid key \"%s\", length (%lud) must be even",
		    string_value, strlen(string_value));
		return LDAP_STORAGE_ERROR;
	}
	// assume 00FFAA - two byte per uint8
	size_t key_l = strlen(string_value) / 2;
	// handle 0x prefix
	key_l = strncmp("0x", string_value, 2) ? key_l: key_l - 1;
	int rc = uint8_array_from_hex_string(string_value, &key, key_l);
	if (0 != rc) {
		return LDAP_STORAGE_ERROR;
	}
	*V = (char*) key;
	*V_l = key_l;
	return LDAP_STORAGE_SUCCESS;
}


int
get_hash_from_string(const char * string_value, char ** V, size_t * V_l)
{
	uint8_t *hash;
	if (strlen(string_value) % 2 != 0) {
		syslog(LOG_ERR, "Invalid hash \"%s\", length must be even",
		    string_value);
		return LDAP_STORAGE_ERROR;
	}
	size_t hash_l = strlen(string_value) / 2;
	hash_l = strncmp("0x", string_value, 2) ? hash_l: hash_l - 1;
	int rc = uint8_array_from_hex_string(string_value, &hash, hash_l);
	if (0 != rc) {
		return LDAP_STORAGE_ERROR;
	}
	*V = (char*) hash;
	*V_l = hash_l;
	return LDAP_STORAGE_SUCCESS;
}


int
get_int_from_string(const char * string_value, char ** V, size_t * V_l)
{
	uint64_t value;
	int rc = uint64_from_hex_string(string_value, &value);
	if (-1 == rc) {
		return rc;
	}
	*V = calloc(1, sizeof(uint64_t));
	memcpy(*V, &value, sizeof(uint64_t));
	*V_l = sizeof(value);
	return LDAP_STORAGE_SUCCESS;
}


/*
 * copy values from ldap_values
 */
int
config_db_get(DB * db, DBT * K, DBT * V)
{
	// ugly.... better with structured ldap fields?
	int r = LDAP_STORAGE_SUCCESS;
	V->data = NULL;
	V->size = 0;
	if (!strcmp(K->data, "suite")) {
		V->data = strdup(db->session->info->suite);
	} else if (!strcmp(K->data, "key")) {
		return get_key_from_string(db->session->info->key,
		    &V->data, &V->size);
	} else if (!strcmp(K->data, "C")) {
		return get_int_from_string(db->session->info->counter,
		    &V->data, &V->size);
	} else if (!strcmp(K->data, "counter_window")) {
		return get_int_from_string(db->session->info->counter_window,
		    &V->data, &V->size);
	} else if (!strcmp(K->data, "P")) {
		return get_hash_from_string(db->session->info->pin_hash,
		    &V->data, &V->size);
	} else if (!strcmp(K->data, "kill_pin")) {
		return get_hash_from_string(db->session->info->kill_pin_hash,
		    &V->data, &V->size);
	} else if (!strcmp(K->data, "timestamp_offset")) {
		return get_int_from_string(db->session->info->pin_hash,
		    &V->data, &V->size);
	} else {
		return LDAP_STORAGE_ERROR;
	}
	if (NULL != V->data) {
		V->size = strlen(V->data);
	}
	return r;
};

int
config_db_open(DB ** db, int flags, const char *path, const int user_id,
	const char *nodata, const char *fake_suite)
{
	struct passwd *pwd = NULL;

	if (path != NULL) {
		syslog(LOG_ERR, "Open configuration from path not supported for LDAP");
		return LDAP_STORAGE_ERROR;
	}
	/**
	 * Open by user_id
	 */

	if (NULL == (pwd = getpwuid(user_id))) {
		syslog(LOG_ERR, "getpwuid failed: %s", strerror(errno));
		return LDAP_STORAGE_ERROR;
	}
	/*
	 * Fill ldap_values from remote store
	 */
	const char* config_file = PAM_LDAP_PATH_CONF;

	DB *new_db = calloc(1, sizeof(DB));

	if (LDAP_STORAGE_SUCCESS != get_session(
	    config_file, &new_db->session)) {
		syslog(LOG_ERR, "Failed to get a LDAP session.");
		free(new_db);
		return LDAP_STORAGE_ERROR;
	}
	if (LDAP_STORAGE_SUCCESS != session_open(
	    new_db->session)) {
		syslog(LOG_ERR, "Failed to open a LDAP session.");
		free(new_db);
		return LDAP_STORAGE_ERROR;
	}
	if (LDAP_STORAGE_SUCCESS != get_user_info(
	    new_db->session, pwd->pw_name)) {
		syslog(LOG_ERR, "Failed to read LDAP values.");
		free(new_db);
		return LDAP_STORAGE_ERROR;
	}
	*db = new_db;

	return LDAP_STORAGE_SUCCESS;
}

/**
 * copy value to ldap_config
 */
int
config_db_put(DB * db, DBT * K, DBT * V){
	int r = LDAP_STORAGE_SUCCESS;
	if (!strcmp(K->data, "suite")) {
		db->session->info->suite = strdup(V->data);
	} else if (!strcmp(K->data, "key")) {
		return hex_string_from_uint8_array(
		    (uint8_t*)V->data, V->size, &db->session->info->key);
	} else if (!strcmp(K->data, "C")) {
		return hex_string_from_uint64(
			(uint8_t*)V->data, V->size, &db->session->info->counter);
	} else if (!strcmp(K->data, "counter_window")) {
		return hex_string_from_uint64(
			(uint8_t*)V->data, V->size, &db->session->info->counter_window);
	} else if (!strcmp(K->data, "P")) {
		return hex_string_from_uint8_array(
		    (uint8_t*)V->data, V->size, &db->session->info->pin_hash);
	} else if (!strcmp(K->data, "kill_pin")) {
		return hex_string_from_uint8_array(
		    (uint8_t*)V->data, V->size, &db->session->info->kill_pin_hash);
	} else if (!strcmp(K->data, "timestamp_offset")) {
		return hex_string_from_uint64(
			(uint8_t*)V->data, V->size, &db->session->info->timestamp_offset);
	} else {
		return LDAP_STORAGE_ERROR;
	}
	if (NULL != V->data) {
		V->size = strlen(V->data);
	}	return r;
}

/**
 * store values from ldap_config to remote
 */
int
config_db_sync(DB * db){

	int r = LDAP_STORAGE_SUCCESS;

	if (NULL == db->session) {
		fprintf(stderr, "No session to sync with.\n");
		return LDAP_STORAGE_ERROR;
	}
	if (LDAP_STORAGE_SUCCESS != store_user_info(
	    db->session)) {
		syslog(LOG_ERR, "Failed to write LDAP values.");
		return LDAP_STORAGE_ERROR;
	}

	return r;
}
