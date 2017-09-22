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

#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include <ldap_storage.h>
#include <ldap_storage_rebind.h>
#include <ldap_storage_util.h>

/**
 * Escape String
 *
 * Backslash escape the given input.
 *
 * @param input
 * String to be escaped.
 *
 * @param out
 * String buffer to write the escaped values.
 * "my(name)is\\es*ped" will be
 * "my\\28name\\29is\\5ces\\2aped"
 *
 * @param outlen
 * Size of the out buffer.
 *
 * @return LDAP_STORAGE_SUCCESS when the output was converted correctly.
 */
int
escape_string (const char *input, char *out, size_t outlen)
{
    int rc = LDAP_STORAGE_BUF_ERR;
    char *p = out;
    char *limit = p + outlen - 3;
    const char *s = input;

    while (p < limit && *s) {
        switch (*s) {
            case '*':
                strcpy(p, "\\2a");
                p += 3;
                break;
            case '(':
                strcpy(p, "\\28");
                p += 3;
                break;
            case ')':
                strcpy(p, "\\29");
                p += 3;
                break;
            case '\\':
                strcpy(p, "\\5c");
                p += 3;
                break;
            default:
                *p++ = *s;
                break;
        }
        s++;
    }

    if ('\0' == *s) {
        /* got to end */
        *p = '\0';
        rc = LDAP_STORAGE_SUCCESS;
    }

    return rc;
}


/**
 * LDAP get lderrno
 *
 * Optional implementation for libraries that do not provide ldap_get_lderrno.
 * Obtains information for the most recent error that occurred for an LDAP
 * operation.
 *
 * @param ld
 * Pointer to a session->ld
 *
 * @param matcheddnp
 * Returns the matched distinguished name from the most recent result message.
 *
 * @param errmsgp
 * Returns the error text from the most recent result message.
 */
#ifndef HAVE_LDAP_GET_LDERRNO
int
ldap_get_lderrno(LDAP * ld, char ** matcheddnp, char ** errmsgp)
{
#ifdef HAVE_LDAP_GET_OPTION
    int rc;
#endif
    int lderrno;

#if defined(HAVE_LDAP_GET_OPTION) && defined(LDAP_OPT_ERROR_NUMBER)
    /* is this needed? */
    rc = ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &lderrno);
    if (LDAP_SUCCESS != rc) {
        return rc;
    }
#else
    lderrno = ld->ld_errno;
#endif

    if (NULL != errmsgp) {
#if defined(HAVE_LDAP_GET_OPTION) && defined(LDAP_OPT_ERROR_STRING)
        rc = ldap_get_option(ld, LDAP_OPT_ERROR_STRING, errmsgp);
        if (LDAP_SUCCESS != rc) {
            return rc;
        }
#else
        *errmsgp = ld->ld_error;
#endif
    }

    if (NULL != matcheddnp) {
#if defined(HAVE_LDAP_GET_OPTION) && defined(LDAP_OPT_MATCHED_DN)
        rc = ldap_get_option(ld, LDAP_OPT_MATCHED_DN, matcheddnp);
        if (LDAP_SUCCESS != rc) {
            return rc;
        }
#else
        *matcheddnp = ld->ld_matched;
#endif
    }

    return lderrno;
}
#endif
