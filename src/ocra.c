/*-
 * Copyright (c) 2014 Stefan Grundmann
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

#include <sys/types.h>
#include <pwd.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <fcntl.h>
#include <syslog.h>
#include <errno.h>

#include <security/pam_appl.h>

#include <openssl/evp.h>

#include <rfc6287.h>
#include <db_storage.h>
#include <ocra.h>
#include <storage_key.h>


static int
fake_challenge(const char * suite_string, char ** questions)
{
	int r;
	ocra_suite ocra;

	if (RFC6287_SUCCESS != (r = rfc6287_parse_suite(&ocra, suite_string))) {
		syslog(LOG_ERR, "pam_orca: rfc6287_parse_suite() failed for "
		    "fake_challenge \"%s\": %s", suite_string, rfc6287_err(r));
		return PAM_SERVICE_ERR;
	}
	if (RFC6287_SUCCESS != (r = rfc6287_challenge(&ocra, questions))) {
		syslog(LOG_ERR, "pam_orca: rfc6287_challenge() failed: %s",
		    rfc6287_err(r));
		return PAM_SERVICE_ERR;
	}
	/* Indicate that a fake challenge was returned */
	return PAM_NO_MODULE_DATA;
}


int
challenge(const char * path, const char * user_name, char ** questions,
    const char * nodata, const char * fake_suite)
{
	int r;
	DB *db = NULL;
	DBT K, V;
	int user_id;

	struct passwd *pwd = NULL;

	ocra_suite ocra;

	memset(&K, 0, sizeof(K));
	memset(&V, 0, sizeof(V));

	errno = 0;
	if (NULL == (pwd = getpwnam(user_name))) {
		syslog(LOG_ERR, "pam_orca: Challenge failure getting user_id: %s",
		    strerror(errno));
		return PAM_SERVICE_ERR;
	}
	user_id = pwd->pw_uid;


	if (0 != config_db_open(&db, DB_OPEN_FLAGS_RO, path,
	    user_id, nodata, fake_suite)) {
		syslog(LOG_ERR, "pam_orca: Configuration for user \"%s\""
		    " cannot be opened.",
		    user_name);
		/* Handle file open errors */
		if (NULL != path) {
			if (NULL != fake_suite) {
				/* Indicate that a fake challenge must be generated */
				r = PAM_NO_MODULE_DATA;
			} else if (NULL == nodata || strcmp(nodata, "fail") == 0) {
				/* We know we want to fail, so log an error. */
				syslog(LOG_ERR, "pam_orca: challenge dbopen(\"%s\", ...)"
				    " failed: %s",
				    path, strerror(errno));
				r = PAM_AUTHINFO_UNAVAIL;
			} else {
				/* We will be changing the return code later */
				r = PAM_AUTHINFO_UNAVAIL;
			}
			if (PAM_NO_MODULE_DATA == r ) {
				r = fake_challenge(fake_suite, questions);
			}
			return r;
		}
		return PAM_SERVICE_ERR;
	}


	KEY(K, "suite");
	if (0 != config_db_get(db, &K, &V)) {
		config_db_close(db);
		return PAM_SERVICE_ERR;
	}
	r = rfc6287_parse_suite(&ocra, V.data);

	config_db_close(db);

	if (RFC6287_SUCCESS != r) {
		syslog(LOG_ERR, "pam_orca: challenge: rfc6287_parse_suite() failed: %s",
		    rfc6287_err(r));
		return PAM_SERVICE_ERR;
	}
	if (RFC6287_SUCCESS != (r = rfc6287_challenge(&ocra, questions))) {
		syslog(LOG_ERR, "pam_orca: rfc6287_challenge() failed: %s",
		    rfc6287_err(r));
		return PAM_SERVICE_ERR;
	}
	return PAM_SUCCESS;
}


int
verify(const char * path, const char * user_name, const char * questions,
    const char * response)
{
	int ret = PAM_SERVICE_ERR;
	int r;
	DB *db = NULL;
	DBT K, V;

	char *suite_string = NULL;
	uint8_t *key = NULL;
	size_t key_l = 0;
	uint64_t C = 0;
	uint8_t *P = NULL;
	size_t P_l = 0;
	uint8_t *KP = NULL;
	size_t KP_l = 0;
	uint64_t T = 0;
	int counter_window = 0;
	int timestamp_offset = 0;
	uint64_t next_counter;
	ocra_suite ocra;
	int user_id;

	struct passwd *pwd = NULL;

	memset(&K, 0, sizeof(K));
	memset(&V, 0, sizeof(V));

	errno = 0;
	if (NULL == (pwd = getpwnam(user_name))) {
		syslog(LOG_ERR, "pam_orca: verify failure getting user_id: %s",
		    strerror(errno));
		return PAM_SERVICE_ERR;
	}
	user_id = pwd->pw_uid;

	/*
	 * This function should only be called if there was valid OCRA data for
	 * the user.  Fail out if it doesn't exist.
	 */
	r = config_db_open(&db, DB_OPEN_FLAGS_RW, path, user_id, NULL, NULL);
	if (PAM_SUCCESS != r) {
		return r;
	}

	KEY(K, "suite");
	if (0 != config_db_get(db, &K, &V))
		goto out;
	if (NULL == (suite_string = (char *)malloc(V.size + 1))) {
		syslog(LOG_ERR, "pam_orca: verify: malloc() failed: %s",
		    strerror(errno));
		goto out;
	}
	memcpy(suite_string, V.data, V.size + 1);

	if (RFC6287_SUCCESS != (r = rfc6287_parse_suite(&ocra, suite_string))) {
		syslog(LOG_ERR, "pam_orca: verify: rfc6287_parse_suite(%s) failed: %s",
		    suite_string, rfc6287_err(r));
		goto out;
	}
	KEY(K, "key");
	if (0 != config_db_get(db, &K, &V)) {
		goto out;
	}
	if (NULL == (key = (uint8_t *)malloc(V.size))) {
		syslog(LOG_ERR, "pam_orca: verify: malloc() failed: %s",
		    strerror(errno));
		goto out;
	}
	memcpy(key, V.data, V.size);
	key_l = V.size;

	if (ocra.flags & FL_C) {
		KEY(K, "C");
		if (0 != config_db_get(db, &K, &V)) {
			goto out;
		}
		memcpy(&C, V.data, sizeof(C));

		KEY(K, "counter_window");
		if (0 != config_db_get(db, &K, &V)) {
			goto out;
		}
		memcpy(&counter_window, V.data, sizeof(counter_window));
	}
	if (ocra.flags & FL_P) {
		KEY(K, "P");
		if (0 != config_db_get(db, &K, &V)) {
			goto out;
		}
		if (NULL == (P = (uint8_t *)malloc(V.size))) {
			syslog(LOG_ERR, "pam_orca: verify: malloc() failed: %s",
			    strerror(errno));
			goto out;
		}
		memcpy(P, V.data, V.size);
		P_l = V.size;
		KEY(K, "kill_pin");
		if (0 != config_db_get(db, &K, &V)) {
			goto out;
		}
		if (NULL == (KP = (uint8_t *)malloc(V.size))) {
			syslog(LOG_ERR, "pam_orca: verify: malloc() failed: %s",
			    strerror(errno));
			goto out;
		}
		memcpy(KP, V.data, V.size);
		KP_l = V.size;
	}
	if (ocra.flags & FL_T) {
		KEY(K, "timestamp_offset");
		if (0 != config_db_get(db, &K, &V)) {
			goto out;
		}
		memcpy(&timestamp_offset, V.data, sizeof(timestamp_offset));

		if (0 != rfc6287_timestamp(&ocra, &T)) {
			syslog(LOG_ERR, "pam_orca: verify: rfc6287_timestamp() failed: %s",
			    rfc6287_err(r));
			goto out;
		}
	}
	if (NULL != KP) {
		/*
		 * Kill pin check
		 */
		r = rfc6287_verify(&ocra, suite_string, key, key_l, C, questions,
		    KP, KP_l, NULL, 0, T, response, counter_window, &next_counter,
		    timestamp_offset);
		if (RFC6287_SUCCESS == r) {
			/* avoid timing detection */
			r = rfc6287_verify(&ocra, suite_string, key, key_l, C, questions,
			    P, P_l, NULL, 0, T, response, counter_window, &next_counter,
			    timestamp_offset);
			syslog(LOG_ERR,
			    "pam_orca: Authentication Success for user %s with kill_pin",
			    user_name);
			ret = PAM_AUTH_ERR;

			/* make key invalid for future uses */
			KEY(K, "key");
			// XXX random bytes, otherwise predictable?
			key[0] = key[0] + 1;
			V.data = &key;
			V.size = key_l;
			syslog(LOG_USER, "pam_orca: Key updated to invalid by kill pin.");
			if (0 != config_db_put(db, &K, &V)) {
				syslog(LOG_ERR, "pam_orca: db->put() failed for %s: %s",
				    (const char *)(K.data),
				    strerror(errno));
				goto out;
			}
			goto out;
		}
	}
	r = rfc6287_verify(&ocra, suite_string, key, key_l, C, questions,
	    P, P_l, NULL, 0, T, response, counter_window, &next_counter,
	    timestamp_offset);
	if (RFC6287_SUCCESS == r) {
		if (ocra.flags & FL_C) {
			KEY(K, "C");
			V.data = &next_counter;
			V.size = sizeof(uint64_t);
			syslog(LOG_USER, "pam_orca: Counter updated to %02x.",
			    ((uint8_t)(next_counter)));
			if (0 != config_db_put(db, &K, &V)) {
				syslog(LOG_ERR, "pam_orca: db->put() failed for %s: %s",
				    (const char *)(K.data),
				    strerror(errno));
				goto out;
			}
		}
		ret = PAM_SUCCESS;
	} else if (RFC6287_VERIFY_FAILED == r){
		syslog(LOG_ERR,
		    "pam_orca: Authentication Error for user %s with challenge %s "
		    "and response %s", user_name, questions, response);
		ret = PAM_AUTH_ERR;
	} else {
		syslog(LOG_ERR, "pam_orca: rfc6287_challenge() failed: %s",
		    rfc6287_err(r));
	}
out:
	if (0 != config_db_close(db)) {
		syslog(LOG_ERR, "pam_orca: db->close() failed: %s", strerror(errno));
	}
	free(suite_string);
	free(key);
	free(P);
	return ret;
}


int
find_counter(const char * path, const char * user_name,
    const char * questions, const char * response1, const char * response2)
{
	int ret = PAM_SERVICE_ERR;
	int r, rv;
	DB *db = NULL;
	DBT K, V;

	char *suite_string = NULL;
	uint8_t *key = NULL;
	size_t key_l = 0;
	uint64_t C = 0;
	uint8_t *P = NULL;
	size_t P_l = 0;
	uint64_t T = 0;
	int counter_window = 0;
	int timestamp_offset = 0;
	uint64_t next_counter;
	ocra_suite ocra;
	int user_id = 0;
	struct passwd *pwd = NULL;

	memset(&K, 0, sizeof(K));
	memset(&V, 0, sizeof(V));

	errno = 0;
	if (NULL == (pwd = getpwnam(user_name))) {
		syslog(LOG_ERR, "pam_orca: find_counter failure getting user_id: %s",
		    strerror(errno));
		return PAM_SERVICE_ERR;
	}
	user_id = pwd->pw_uid;

	/*
	 * This function will only be called with a valid db file.
	 *  Fail out if it doesn't exist.
	 */
	r = config_db_open(&db, DB_OPEN_FLAGS_RW, path, user_id, NULL, NULL);
	if (PAM_SUCCESS != r) {
		return r;
	}

	KEY(K, "suite");
	if (0 != config_db_get(db, &K, &V)) {
		goto out;
	}
	if (NULL == (suite_string = (char *)malloc(V.size))) {
		syslog(LOG_ERR, "pam_orca: malloc() failed: %s", strerror(errno));
		goto out;
	}
	memcpy(suite_string, V.data, V.size);

	if (RFC6287_SUCCESS != (r = rfc6287_parse_suite(&ocra, suite_string))) {
		syslog(LOG_ERR, "pam_orca: rfc6287_parse_suite() failed: %s",
		    rfc6287_err(r));
		goto out;
	}
	KEY(K, "key");
	if (0 != config_db_get(db, &K, &V)) {
		goto out;
	}
	if (NULL == (key = (uint8_t *)malloc(V.size))) {
		syslog(LOG_ERR, "pam_orca: malloc() failed: %s", strerror(errno));
		goto out;
	}
	memcpy(key, V.data, V.size);
	key_l = V.size;

	if (ocra.flags & FL_C) {
		KEY(K, "C");
		if (0 != config_db_get(db, &K, &V)) {
			goto out;
		}
		memcpy(&C, V.data, sizeof(C));

		KEY(K, "counter_window");
		if (0 != config_db_get(db, &K, &V)) {
			goto out;
		}
		memcpy(&counter_window, V.data, sizeof(counter_window));
	}
	if (ocra.flags & FL_P) {
		KEY(K, "P");
		if (0 != config_db_get(db, &K, &V)) {
			goto out;
		}
		if (NULL == (P = (uint8_t *)malloc(V.size))) {
			syslog(LOG_ERR, "pam_orca: malloc() failed: %s", strerror(errno));
			goto out;
		}
		memcpy(P, V.data, V.size);
		P_l = V.size;
	}
	if (ocra.flags & FL_T) {
		KEY(K, "timestamp_offset");
		if (0 != config_db_get(db, &K, &V)) {
			goto out;
		}
		memcpy(&timestamp_offset, V.data, sizeof(timestamp_offset));

		if (0 != rfc6287_timestamp(&ocra, &T)) {
			syslog(LOG_ERR, "pam_orca: rfc6287_timestamp() failed: %s",
			    rfc6287_err(r));
			goto out;
		}
	}
	C = 0;
	counter_window = 1;
	while (C < UINT64_MAX) {
		r = rfc6287_verify(&ocra, suite_string, key, key_l, C, questions,
		    P, P_l, NULL, 0, T, response1, counter_window, &next_counter,
		    timestamp_offset);
		C = next_counter;
		if (r != RFC6287_SUCCESS) {
			continue;
		}
		printf("@0x%.16" PRIx64 ".", C);
		rv = rfc6287_verify(&ocra, suite_string, key, key_l, C, questions,
		    P, P_l, NULL, 0, T, response2, counter_window, &next_counter,
		    timestamp_offset);
		C = next_counter;
		if (rv != RFC6287_SUCCESS) {
			printf(" 2nd verify does not match.\n");
			continue;
		}
		printf(" 2nd verify match.\n");
		printf("Found Counter. The next counter is: 0x%.16" PRIx64 ".\n", C);
		printf("Storing counter in db to allow future window checks\n");
		if (ocra.flags & FL_C) {
			KEY(K, "C");
			V.data = &C;
			V.size = sizeof(uint64_t);
			if (0 != config_db_put(db, &K, &V)) {
				syslog(LOG_ERR, "pam_orca: db->put() failed for %s: %s",
				    (const char *)(K.data),
				    strerror(errno));
				goto out;
			}
		}
		break;
	}
out:
	if (0 != config_db_close(db)) {
		syslog(LOG_ERR, "pam_orca: db->close() failed: %s", strerror(errno));
	}
	free(suite_string);
	free(key);
	free(P);
	return ret;
}
