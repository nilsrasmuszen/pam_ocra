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

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <sysexits.h>

#include <fcntl.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#include <rfc6287.h>
#include <db_storage.h>
#include <ocra.h>
#include <pam_prompt.h>
#include <security/pam_modules.h>

#ifndef bsd
#define ishexnumber isxdigit
#endif

static void
pin_hash(const ocra_suite * ocra, const char *pin, uint8_t **P, size_t *P_l)
{
	unsigned int s;
	EVP_MD_CTX ctx;

	*P = NULL;
	*P_l = mdlen(ocra->P_alg);
	EVP_MD_CTX_init(&ctx);

	if (NULL == (*P = (uint8_t *)malloc(*P_l))) {
		err(EX_OSERR, "malloc() failed");
	}

	if ((1 != EVP_DigestInit(&ctx, evp_md(ocra->P_alg))) ||
	    (1 != EVP_DigestUpdate(&ctx, pin, strlen(pin))) ||
	    (1 != EVP_DigestFinal(&ctx, *P, &s)) ||
	    (s != *P_l)) {
		errx(EX_OSERR, "pin_hash() failed: %s",
		    ERR_error_string(ERR_get_error(), NULL));
	}
	EVP_MD_CTX_cleanup(&ctx);
}

static int
parse_counter(const char *in, uint64_t *C)
{
	char *stopped;
	int base = strncmp("0x", in, 2) ? 10 : 16;

	if ('-' == in[0]) {
		return -1;
	}
	*C = strtouq(in, &stopped, base);
	if (ULLONG_MAX == *C || 0 == *C) {
		if (errno)
			return -1;
	}
	if (*stopped)
		return -1;
	return 0;
}

static int
parse_num(const char *in)
{
	char *stopped;
	int x = (int)strtol(in, &stopped, 10);

	if (*stopped || (0 > x)) {
		return -1;
	}
	return x;
}

static int
from_hex(const char *in, uint8_t **out, size_t len)
{
	uint32_t i;

	//XXX len-check, assert
	if (0 == strncmp("0x", in, 2)) {
		in += 2;
	}
	if (strlen(in) % 2 == 1) {
		printf("number of chars in key not correct\n");
		return -1;
	}
	if (NULL == (*out = (uint8_t *)malloc(len))) {
		return -1;
	}
	for (i = 0; i < len; i++) {
		if (1 != sscanf(&in[i * 2], "%2hhx", *out + i)) {
			fprintf(stderr, "scanf %%2hhx failed.\n");
			free(*out);
			return -1;
		}
		if (!ishexnumber(toupper(in[(i * 2) + 1]))) {
			fprintf(stderr, "ishexnumber \"%c\"@%d failed.\n", in[(i * 2) + 1], i);
			free(*out);
			return -1;
		}
	}
	return 0;
}

static void
usage(void)
{
	fprintf(stderr,
	    "usage: ocra_tool init -f credential_file -k key -s suite_string\n"
	    "                     [-c counter] [-p pin | -P pin_hash]\n"
	    "                     [-q kill_pin | -Q kill_pin_hash]\n"
	    "                     [-w counter_window] [-t timestamp_offset]\n"
	    "       ocra_tool info -f credential_file\n"
	    "       ocra_tool sync_counter -f credential_file\n"
	    "                 -c challenge\n"
	    "                 -r response -v second_response\n"
	    "       ocra_tool test -f credential_file\n");
	exit(-1);
}

static void
cmd_info(int argc, char **argv)
{
	int ch, ret;
	uint32_t i;
	char *fname = NULL;
	ocra_suite ocra;

	const char *nodata = NULL;
	const char *fake_suite = NULL;

	DB *db;
	DBT K, V;

	int user_id = geteuid();

	while (-1 != (ch = getopt(argc, argv, "f:"))) {
		switch (ch) {
		case 'f':
			if (NULL != fname)
				usage();
			fname = optarg;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	if ((0 != argc) ||
	    (NULL == fname))
		usage();

	memset(&K, 0, sizeof(K));
	memset(&V, 0, sizeof(V));

	if (0 != (config_db_open(&db, DB_OPEN_FLAGS_RO, fname,
	    user_id, nodata, fake_suite))) {
		err(EX_OSERR, "dbopen() failed");
	}
	KEY(K, "suite");
	if (0 != (ret = config_db_get(db, &K, &V))) {
		errx(EX_OSERR, "db->get() failed: %s",
		    (1 == ret) ? "key not in db" : strerror(errno));
	}
	printf("suite:\t\t%s\n", (char *)(V.data));

	if (RFC6287_SUCCESS != (ret = rfc6287_parse_suite(&ocra, V.data))) {
		errx(EX_SOFTWARE, "rfc6287_parse_suite() failed: %s",
		    rfc6287_err(ret));
	}

	KEY(K, "key");
	if (0 != (ret = config_db_get(db, &K, &V))) {
		errx(EX_OSERR, "db->get() failed: %s",
		    (1 == ret) ? "key not in db" : strerror(errno));
	}
	if (mdlen(ocra.hotp_alg) != V.size) {
		errx(EX_SOFTWARE, "key size does not match suite!");
	}


	if (ocra.flags & FL_C) {
		uint64_t C;
		int CW;

		KEY(K, "C");
		if (0 != (ret = config_db_get(db, &K, &V))) {
			errx(EX_OSERR, "db->get() failed: %s",
			    (1 == ret) ? "key not in db" : strerror(errno));
		}
		memcpy(&C, V.data, sizeof(C));
		printf("counter:\t0x%.16" PRIx64 "\n", C);

		KEY(K, "counter_window");
		if (0 != (ret = config_db_get(db, &K, &V))) {
			errx(EX_OSERR, "db->get() failed: %s",
			    (1 == ret) ? "key not in db" : strerror(errno));
		}
		memcpy(&CW, V.data, sizeof(CW));
		printf("counter_window: %d\n", CW);
	}
	if (ocra.flags & FL_P) {
		KEY(K, "P");
		if (0 != (ret = config_db_get(db, &K, &V))) {
			errx(EX_OSERR, "db->get() failed: %s",
			    (1 == ret) ? "key not in db" : strerror(errno));
		}

		if (mdlen(ocra.P_alg) != V.size) {
			errx(EX_SOFTWARE, "pin hash size does not match suite!");
		}
		printf("pin_hash:\t0x");
		for (i = 0; V.size > i; i++) {
			printf("%02x", ((uint8_t *)(V.data))[i]);
		}
		printf("\n");

		KEY(K, "kill_pin");
		if (0 == (ret = config_db_get(db, &K, &V))) {
			if (V.size == 0) {
				printf("kill_pin_hash:\tNot Set");
			} else {
				if (mdlen(ocra.P_alg) != V.size) {
					errx(EX_SOFTWARE,
					    "kill pin hash size does not match suite!");
				}
				printf("kill_pin_hash:\t0x");
				for (i = 0; V.size > i; i++) {
					printf("%02x", ((uint8_t *)(V.data))[i]);
				}
			}
		}
		printf("\n");
	}
	if (ocra.flags & FL_T) {
		int TO;

		KEY(K, "timestamp_offset");
		if (0 != (ret = config_db_get(db, &K, &V))) {
			errx(EX_OSERR, "db->get() failed: %s",
			    (1 == ret) ? "key not in db" : strerror(errno));
		}
		memcpy(&TO, V.data, sizeof(TO));
		printf("timestamp_offset: %d\n", TO);
	}
	if (0 != (config_db_close(db))) {
		errx(EX_OSERR, "db->close() failed: %s", strerror(errno));
	}
}

static void
test_input(const ocra_suite * ocra, const char *suite_string,
    const uint8_t *key, size_t key_l, uint64_t C,
    const uint8_t *P, size_t P_l,
    const uint8_t *KP, size_t KP_l,
    int counter_window, int timestamp_offset)
{
	int r;
	uint64_t T;
	uint64_t next_counter;
	char *questions;
	char *response;

	if (RFC6287_SUCCESS != (r = rfc6287_challenge(ocra, &questions))) {
		errx(EX_SOFTWARE, "rfc6287_challenge() failed: %s",
		    rfc6287_err(r));
	}

	if (RFC6287_SUCCESS != (r = rfc6287_timestamp(ocra, &T))) {
		errx(EX_SOFTWARE, "rfc6287_timestamp() failedi: %s",
		    rfc6287_err(r));
	}

	if (RFC6287_SUCCESS != (r = rfc6287_ocra(ocra, suite_string,
	    key, key_l, C, questions, P, P_l, NULL, 0, T, &response))) {
		errx(EX_SOFTWARE, "rfc6287_ocra() failed: %s", rfc6287_err(r));
	}

	if (RFC6287_SUCCESS != (r = rfc6287_verify(ocra, suite_string,
	    key, key_l, C, questions, P, P_l, NULL, 0, T, response,
	    counter_window, &next_counter, timestamp_offset))) {
		errx(EX_SOFTWARE, "rfc6287_verify() failed: %s",
		    rfc6287_err(r));
	}
	if (NULL != KP) {
		if (RFC6287_SUCCESS != (r = rfc6287_ocra(ocra, suite_string,
		    key, key_l, C, questions, KP, KP_l, NULL, 0, T,
		    &response))) {
			errx(EX_SOFTWARE, "rfc6287_ocra() failed: %s", rfc6287_err(r));
		}

		if (RFC6287_SUCCESS != (r = rfc6287_verify(ocra, suite_string,
		    key, key_l, C, questions, KP, KP_l, NULL, 0, T, response,
		    counter_window, &next_counter, timestamp_offset))) {
			errx(EX_SOFTWARE, "rfc6287_verify() failed: %s",
			    rfc6287_err(r));
		}
	}

	free(response);
	free(questions);
}

static void
write_db(const char *fname, const char *suite_string,
    const uint8_t *key, size_t key_l, uint64_t C, const uint8_t *P, size_t P_l,
    const uint8_t *KP, size_t KP_l,
    int counter_window, int timestamp_offset)
{
	DB *db;
	DBT K, V;

	int user_id = geteuid();
	const char *nodata = NULL;
	const char *fake_suite = NULL;

	memset(&K, 0, sizeof(K));
	memset(&V, 0, sizeof(V));

	if (0 != (config_db_open(&db, DB_OPEN_FLAGS_CREATE, fname,
	    user_id, nodata, fake_suite))) {
		err(EX_OSERR, "dbopen() failed");
	}

	KEY(K, "suite");
	VALUE(V, suite_string, strlen(suite_string) + 1);
	if (0 != (config_db_put(db, &K, &V))) {
		err(EX_OSERR, "db->put() suite failed");
	}

	KEY(K, "key");
	VALUE(V, key, key_l);
	if (0 != (config_db_put(db, &K, &V))) {
		err(EX_OSERR, "db->put() key failed");
	}

	KEY(K, "C");
	VALUE(V, &C, sizeof(C));
	if (0 != (config_db_put(db, &K, &V))) {
		err(EX_OSERR, "db->put() count failed");
	}

	KEY(K, "P");
	VALUE(V, P, P_l);
	if (0 != (config_db_put(db, &K, &V))) {
		err(EX_OSERR, "db->put() P failed");
	}

	KEY(K, "kill_pin");
	VALUE(V, KP, KP_l);
	if (0 != (config_db_put(db, &K, &V))) {
		err(EX_OSERR, "db->put() kill_pin failed");
	}

	KEY(K, "counter_window");
	VALUE(V, &counter_window, sizeof(counter_window));
	if (0 != (config_db_put(db, &K, &V))) {
		err(EX_OSERR, "db->put() counter_window failed");
	}

	KEY(K, "timestamp_offset");
	VALUE(V, &timestamp_offset, sizeof(timestamp_offset));
	if (0 != (config_db_put(db, &K, &V))) {
		err(EX_OSERR, "db->put() timestamp_offset failed");
	}

	if (0 != (config_db_sync(db))) {
		err(EX_OSERR, "db->sync() failed");
	}

	if (0 != (config_db_close(db))) {
		err(EX_OSERR, "db->close() failed");
	}
}

static void
cmd_init(int argc, char **argv)
{
	int r;
	int ch;
	char *fname = NULL;
	char *suite_string = NULL;
	char *key_string = NULL;
	char *pin_string = NULL;
	char *pin_hash_string = NULL;
	char *kill_pin_string = NULL;
	char *kill_pin_hash_string = NULL;
	char *counter_string = NULL;
	char *counter_window_string = NULL;
	char *timestamp_offset_string = NULL;

	ocra_suite ocra;
	uint64_t C = 0;
	int timestamp_offset = 0;
	int counter_window = 0;

	uint8_t *P = NULL;
	size_t P_l = 0;
	uint8_t *KP = NULL;
	size_t KP_l = 0;
	uint8_t *key = NULL;
	size_t key_l = 0;

	while (-1 != (ch = getopt(argc, argv, "f:s:k:p:P:q:Q:c:w:t:"))) {
		switch (ch) {
		case 'f':
			if (NULL != fname) {
				usage();
			}
			fname = optarg;
			break;
		case 's':
			if (NULL != suite_string) {
				usage();
			}
			suite_string = optarg;
			break;
		case 'k':
			if (NULL != key_string) {
				usage();
			}
			key_string = optarg;
			break;
		case 'c':
			if (NULL != counter_string) {
				usage();
			}
			counter_string = optarg;
			break;
		case 'p':
			if (NULL != pin_string) {
				usage();
			}
			pin_string = optarg;
			break;
		case 'P':
			if (NULL != pin_hash_string) {
				usage();
			}
			pin_hash_string = optarg;
			break;
		case 'q':
			if (NULL != kill_pin_string) {
				usage();
			}
			kill_pin_string = optarg;
			break;
		case 'Q':
			if (NULL != kill_pin_hash_string) {
				usage();
			}
			kill_pin_hash_string = optarg;
			break;
		case 'w':
			if (NULL != counter_window_string) {
				usage();
			}
			counter_window_string = optarg;
			break;
		case 't':
			if (NULL != timestamp_offset_string) {
				usage();
			}
			timestamp_offset_string = optarg;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	if ((0 != argc) ||
	    (NULL == fname) ||
	    (NULL == suite_string) ||
	    (NULL == key_string)) {
		usage();
	}

	if (RFC6287_SUCCESS != (r = rfc6287_parse_suite(&ocra, suite_string))) {
		err(EX_CONFIG, "rfc6287_parse_suite() failed: %s",
		    rfc6287_err(r));
	}

	if (ocra.flags & FL_C) {
		if (NULL == counter_string) {
			errx(EX_CONFIG, "suite requires counter parameter "
			    "(-c <counter> missing)");
		}
		if (-1 == parse_counter(counter_string, &C)) {
			errx(EX_CONFIG, "invalid counter value");
		}
		if (NULL != counter_window_string) {
			if (-1 ==
			    (counter_window = parse_num(counter_window_string))) {
				errx(EX_CONFIG, "invalud counter window value");
			}
		}
	} else {
		if (NULL != counter_string) {
			errx(EX_CONFIG, "suite does not require counter "
			    "parameter (-c <counter> must not be set)");
		}
		if (NULL != counter_window_string) {
			errx(EX_CONFIG, "suite does not require counter "
			    "parameter  (-w <counter_window> must not be set)");
		}
	}

	if (ocra.flags & FL_S) {
		errx(EX_CONFIG, "suite requires session parameter (S) which"
		    " is not supported by pam_ocra");
	}

	if (ocra.flags & FL_T) {
		if (-1 ==
		    (timestamp_offset = parse_num(timestamp_offset_string))) {
			errx(EX_CONFIG, "invalid timestamp offset value");
		}
	} else if (NULL != timestamp_offset_string) {
		errx(EX_CONFIG, "suite does nor require timestamp parameter "
		    " (-t <timestamp_offset> must not be set)");
	}
	if (0 == ocra.hotp_trunc) {
		errx(EX_CONFIG, "suite specifies no (0) truncation in "
		    "CryptoFunction. This is not supported by pam_ocra");
	}

	if (ocra.flags & FL_P) {
		if (NULL != pin_string && NULL != pin_hash_string) {
			errx(EX_CONFIG, "exactly one of -p <pin> and -P "
			    "<pin_hash> must be set");
		}
		if (NULL != pin_string) {
			pin_hash(&ocra, pin_string, &P, &P_l);
		} else if (NULL != pin_hash_string) {
			P_l = mdlen(ocra.P_alg);
			if (0 != from_hex(pin_hash_string, &P, P_l)) {
				errx(EX_CONFIG, "invalid pin_hash");
			}
		} else {
			errx(EX_CONFIG, "suite requires pin parameter "
			    "(-p <pin> or -P <pin_hash> missing)");
		}
		if (NULL != kill_pin_string) {
			pin_hash(&ocra, kill_pin_string, &KP, &KP_l);
		} else if (NULL != pin_hash_string) {
			KP_l = mdlen(ocra.P_alg);
			if (0 != from_hex(pin_hash_string, &KP, KP_l)) {
				errx(EX_CONFIG, "invalid kill_pin_hash");
			}
		}
	} else if (NULL != pin_string || NULL != pin_hash_string ||
	    NULL != kill_pin_string || NULL != kill_pin_hash_string) {
		errx(EX_CONFIG, "suite does not require pin parameter"
		    " (-p <pin>, -P <pin_hash>, -q <kill_pin> or -Q <kill_pin_hash>"
		    " must not be set)");
	}

	key_l = mdlen(ocra.hotp_alg);
	if (0 != from_hex(key_string, &key, key_l)) {
		errx(EX_CONFIG, "invalid key");
	}

	test_input(&ocra, suite_string, key, key_l, C, P, P_l, KP, KP_l,
	    counter_window, timestamp_offset);

	unlink(fname);
	write_db(fname, suite_string, key, key_l, C, P, P_l, KP, KP_l,
	    counter_window, timestamp_offset);

}

static void
cmd_sync_counter(int argc, char **argv)
{
	int ch, ret;
	uint32_t i;
	char *fname = NULL;
	char *challenge = NULL;
	char *response1 = NULL;
	char *response2 = NULL;
	ocra_suite ocra;

	const char *nodata = NULL;
	const char *fake_suite = NULL;

	DB *db;
	DBT K, V;

	uint64_t C;
	int CW;

	int user_id = geteuid();

	while (-1 != (ch = getopt(argc, argv, "f:c:r:v:"))) {
		switch (ch) {
		case 'f':
			if (NULL != fname) {
				usage();
			}
			fname = optarg;
			break;
		case 'c':
			if (NULL != challenge) {
				usage();
			}
			challenge = optarg;
			break;
		case 'r':
			if (NULL != response1) {
				usage();
			}
			response1 = optarg;
			break;
		case 'v':
			if (NULL != response2) {
				usage();
			}
			response2 = optarg;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	if ((0 != argc) ||
	    (NULL == fname)) {
		usage();
	}

	memset(&K, 0, sizeof(K));
	memset(&V, 0, sizeof(V));

	if (strlen(challenge) != 8) {
		err(EX_SOFTWARE, "Challenge with 8 bytes required");
	}
	if (strlen(response1) != 6) {
		err(EX_SOFTWARE, "Response with 6 bytes required");
	}
	if (strlen(response2) != 6) {
		err(EX_SOFTWARE, "Validation with 6 bytes required");
	}

	printf("Brute forcing verify function...\n");
	find_counter(fname, challenge, response1, response2);
	printf("done\n");
}

static void
cmd_test(int argc, char **argv)
{
	int ch, ret, qret, cpad;
	uint32_t i;
	char *fname = NULL;
	char response[64];
	char fmt[512];
	char *questions;
	char *cmsg;
	char *rmsg;
	const char* FAKE_USER = "root";  // this user must exist

	ocra_suite ocra;

	DB *db;
	DBT K, V;

	uint64_t C;
	int CW;

	int user_id = geteuid();

	while (-1 != (ch = getopt(argc, argv, "f:"))) {
		switch (ch) {
		case 'f':
			if (NULL != fname) {
				usage();
			}
			fname = optarg;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	if ((0 != argc) ||
	    (NULL == fname)) {
		usage();
	}

	memset(&K, 0, sizeof(K));
	memset(&V, 0, sizeof(V));

	printf("Tail the syslog to see module output.\n");

	qret = challenge(fname, FAKE_USER, &questions, NULL, NULL);
	if (PAM_SUCCESS != qret && PAM_NO_MODULE_DATA != qret) {
		printf("No challenge was generated.\n");
		return;
	}
	make_prompt(fmt, sizeof(fmt), questions,
		PROMPT_CHALLENGE, PROMPT_RESPONSE, PROMPT_ACCESSIBLE_PAD);

	printf("Default prompt:\n\n%s", fmt);
	fgets(response, sizeof(response), stdin);

	ret = verify(fname, FAKE_USER, questions, response);
	if (PAM_SUCCESS == ret) {
		printf("Success.\n");
	} else {
		printf("Failure.\n");
	}
}

int
main(int argc, char **argv)
{
	if (2 > argc) {
		usage();
	}
	if (0 == strcmp(argv[1], "init")) {
		cmd_init(argc - 1, argv + 1);
	} else if (0 == strcmp(argv[1], "info")) {
		cmd_info(argc - 1, argv + 1);
	} else if (0 == strcmp(argv[1], "sync_counter")) {
		cmd_sync_counter(argc - 1, argv + 1);
	} else if (0 == strcmp(argv[1], "test")) {
		cmd_test(argc - 1, argv + 1);
	} else {
		usage();
	}
	return 0;
}
