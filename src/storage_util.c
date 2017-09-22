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
#define _GNU_SOURCE /* asprintf */
#include <ctype.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#ifndef __FreeBSD__
#define ishexnumber isxdigit
#endif

#define UTIL_ERROR -1
#define UTIL_SUCCESS 0

int
uint8_array_from_hex_string(const char * in, uint8_t ** out, size_t len)
{
	uint32_t i;
	if (0 == strcmp("0", in) || 0 == strcmp("", in) ) {
		out[0] = 0;
		return UTIL_SUCCESS;
	}
	if (strlen(in) < 2) {
		fprintf(stderr, "Value \"%s\" needs to be at least 2 characters.\n",
			in);
		return UTIL_ERROR;
	}
	if (0 == strncmp("0x", in, 2)) {
		in += 2;
	}
	if (strlen(in) < 2) {
		fprintf(stderr, "Value %s needs to be at least 2 characters.\n", in);
		return UTIL_ERROR;
	}
	if (strlen(in) % 2 == 1) {
		fprintf(stderr, "Number of chars in hex string %s not correct\n", in);
		return UTIL_ERROR;
	}
	if (NULL == (*out = (uint8_t *)malloc(len))) {
		fprintf(stderr, "Failed to allocate memory: %s\n", strerror(errno));
		return UTIL_ERROR;
	}
	for (i = 0; i < len; i++) {
		if (1 != sscanf(&in[i * 2], "%2hhx", *out + i)) {
			fprintf(stderr, "Scanf %%2hhx failed: %s. %s[%d].\n", strerror(errno),
			    in, i);
			free(*out);
			return UTIL_ERROR;
		}
		if (!ishexnumber(toupper(in[(i * 2) + 1]))) {
			fprintf(stderr, "Ishexnumber \"%c\"@%d failed: %s\n",
			    in[(i * 2) + 1], i, strerror(errno));
			free(*out);
			return UTIL_ERROR;
		}
	}
	return UTIL_SUCCESS;
}

int
uint64_from_hex_string(const char *in, uint64_t *out)
{
	char *stopped;
	int base = strncmp("0x", in, 2) ? 10 : 16;

	if ('-' == in[0]) {
		fprintf(stderr, "Negative numbers not supported.\n");
		return UTIL_ERROR;
	}
	*out = strtouq(in, &stopped, base);
	if (ULLONG_MAX == *out || 0 == *out) {
		if (errno) {
			fprintf(stderr, "strtouq failed: %s %s.\n", in,  strerror(errno));
			return UTIL_ERROR;
		}
	}
	if (*stopped) {
		fprintf(stderr, "strtouq failed: %s %s.\n", in, strerror(errno));
		return UTIL_ERROR;
	}
	return UTIL_SUCCESS;
}


int
hex_string_from_uint8_array(const uint8_t *in, size_t len, char ** out)
{
	uint32_t i;
	int rc = UTIL_SUCCESS;
	char *hex_numbers = strdup("");
	char buf_instance[3];
	char *buf_hex_numbers = NULL;
	if (NULL == in) {
		*out = strdup("");
		goto cleanup;
	}
	if (0 == len) {
		*out = strdup("");
		goto cleanup;
	}

	for (i = 0; i < len; i++) {
		if (-1 == snprintf(buf_instance, sizeof(buf_instance), "%02x", in[i])) {
			fprintf(stderr, "snprintf failed: %s.\n", strerror(errno));
			rc = UTIL_ERROR;
			goto cleanup;
		}
		if (NULL != buf_hex_numbers) {
			free(hex_numbers);
			hex_numbers = strdup(buf_hex_numbers);
			free(buf_hex_numbers);
			buf_hex_numbers = NULL;
		}
		if (-1 == asprintf(&buf_hex_numbers, "%s%s",
		    hex_numbers, buf_instance)) {
			fprintf(stderr, "asprintf failed: %s.\n", strerror(errno));
			rc = UTIL_ERROR;
			goto cleanup;
		}
	}
	free(hex_numbers);
	if (NULL != buf_hex_numbers) {
		hex_numbers = strdup(buf_hex_numbers);
		free(buf_hex_numbers);
		buf_hex_numbers = NULL;
		if (-1 == asprintf(out, "0x%s", hex_numbers)) {
			fprintf(stderr, "asprintf failed: %s.\n", strerror(errno));
			rc = UTIL_ERROR;
			goto cleanup;
		}
	} else {
		if (-1 == asprintf(out, "0x0")) {
			fprintf(stderr, "asprintf failed: %s.\n", strerror(errno));
			rc = UTIL_ERROR;
			goto cleanup;
		}
	}
	cleanup:
	if (NULL != hex_numbers) {
		free(hex_numbers);
	}
	if (NULL != buf_hex_numbers) {
		free(buf_hex_numbers);
	}
	return rc;
}


int
hex_string_from_uint64(const uint8_t *in, size_t len, char ** out)
{
	uint64_t value;
	int rc = UTIL_SUCCESS;
	if (NULL == in || 0 == len) {
		*out = strdup("");
		goto cleanup;
	}
	memcpy(&value, in, sizeof(uint64_t));
	if (-1 == asprintf(out, "0x%02x", value)) {
		fprintf(stderr, "asprintf failed: %s.\n", strerror(errno));
		rc = UTIL_ERROR;
		goto cleanup;
	}

	cleanup:
	return rc;
}
