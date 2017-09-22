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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <string.h>

#include <pam_prompt.h>

static void
fmt_prompt(char *mbuf, int msize, const char *questions, const char *pmsg,
    int cpad)
{
    char *mptr = mbuf;
    const char *pptr = pmsg;
    int mrsize = 0;
    int qlen = strlen(questions);
    int qpos = 0;
    time_t epoch_seconds;
    struct tm *now;

    msize--;            /* Ensure we always have room for
                     * trailing '\0' */
    if (NULL != pmsg) {
        while ((mrsize < msize) && *pptr != '\0') {
            /* Copy over the first part of the string */
            while ((mrsize < msize) && *pptr != '\0') {
                if (*pptr != '%') {
                    *mptr++ = *pptr++;
                    mrsize++;
                } else {
                    pptr++;
                    break;
                }
            }

            /*
             * Handle the conversion character.  If not understood,
             * the '%' will be quitely dropped.
             */
            switch (*pptr) {
            case '%':   /* Literal '%' */
                *mptr++ = '%';
                mrsize++;
                pptr++;
                break;

            case '_':   /* Literal ' ' */
                *mptr++ = ' ';
                mrsize++;
                pptr++;
                break;

            case 'u':   /* UTC time */
                time(&epoch_seconds);
                now = gmtime(&epoch_seconds);
                strftime(mptr, msize - mrsize,
                    "%Y-%m-%dT%H:%M:%SZ", now);
                mrsize = strlen(mbuf);
                mptr = &mbuf[mrsize];
                pptr++;
                break;

            case 'l':   /* Local time */
                time(&epoch_seconds);
                now = localtime(&epoch_seconds);
                strftime(mptr, msize - mrsize,
                    "%Y-%m-%dT%H:%M:%S%z %Z", now);
                mrsize = strlen(mbuf);
                mptr = &mbuf[mrsize];
                pptr++;
                break;

            case 'c':   /* Challenge question */
                snprintf(mptr, msize - mrsize,
                    "%s", questions);
                mrsize = strlen(mbuf);
                mptr = &mbuf[mrsize];
                pptr++;
                break;

            case 'a':   /* Accessible Challenge question */
                for (qpos = 0; qpos < strlen(questions); qpos++) {
                    snprintf(mptr, msize - mrsize,
                        "%c", questions[qpos]);
                    mrsize = strlen(mbuf);
                    mptr = &mbuf[mrsize];
                    if (qpos == qlen - 1) {
                        /* Avoid trailing blank */
                        continue;
                    }
                    if (cpad <= 0) {
                        continue;
                    }
                    if ((qpos + 1) % cpad == 0) {
                        snprintf(mptr, msize - mrsize, " ");
                        mrsize = strlen(mbuf);
                        mptr = &mbuf[mrsize];
                    }
                }
                pptr++;
                break;
            }
        }

    }
    /* Terminate the prompt string */
    *mptr = '\0';
}

void
make_prompt(char *buf, int bsize, const char *questions,
    const char *cmsg, const char *rmsg, int cpad)
{
    char cbuf[512];
    char rbuf[512];

    /* Create the default prompt strings, if necessary */
    if (NULL == cmsg && NULL == rmsg) {
        cmsg = PROMPT_CHALLENGE;
        rmsg = PROMPT_RESPONSE;
    }
    /* Generate each prompt */
    fmt_prompt(cbuf, sizeof(cbuf), questions, cmsg, cpad);
    fmt_prompt(rbuf, sizeof(rbuf), questions, rmsg, cpad);

    /* Concatinate them to the final prompt */
    if (NULL != cmsg && NULL != rmsg) {
        snprintf(buf, bsize, "%s\n%s", cbuf, rbuf);
    } else if (NULL != cmsg) {
        snprintf(buf, bsize, "%s\n", cbuf);
    } else {
        snprintf(buf, bsize, "%s", rbuf);
    }
}
