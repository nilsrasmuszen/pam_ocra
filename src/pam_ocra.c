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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>

#include <security/pam_modules.h>
#include <security/pam_appl.h>

#include <ocra.h>
#include <pam_prompt.h>

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

#ifndef _OPENPAM
static char password_prompt[] = "Password:";
#endif

#define LOG_NAME "pam_ocra"
#define MODULE_NAME "pam_ocra"

static int
adjust_return(const char *nodata, int ret)
{
	if (PAM_SUCCESS != ret && (PAM_AUTHINFO_UNAVAIL == ret ||
	    PAM_NO_MODULE_DATA == ret)) {
		/* Change the return code, if requested */
		if (NULL != nodata) {
			if (strcmp(nodata, "succeed") == 0) {
				ret = PAM_SUCCESS;
			} else if (strcmp(nodata, "ignore") == 0) {
				ret = PAM_IGNORE;
			} else if (strcmp(nodata, "fail") != 0) {
				syslog(LOG_ERR, "Unknown \"nodata\" value");
				ret = PAM_SERVICE_ERR;
			}
		}
		/*
		 * PAM_NO_MODULE_DATA is the result when a fake prompt is
		 * displayed.  If not handled above, treat it like an
		 * authentication failure.
		 */
		if (PAM_NO_MODULE_DATA == ret) {
			ret = PAM_AUTH_ERR;
		}
	}
	return ret;
}

static int
get_response(pam_handle_t *pamh, char *prompt, char **response)
{
	int ret;
	struct pam_message msg;
	const struct pam_message *msgp = &msg;
	const struct pam_conv *conv = NULL;
	struct pam_response *presponse = NULL;

	pam_get_item(pamh, PAM_CONV, (const void **)&conv);
	pam_set_item(pamh, PAM_AUTHTOK, NULL);

	msg.msg_style = PAM_PROMPT_ECHO_ON;
	msg.msg = prompt;

	ret = (*conv->conv) (1, &msgp, &presponse, conv->appdata_ptr);

	if (NULL != presponse) {
		if (PAM_SUCCESS == ret) {
			*response = presponse->resp;
			presponse->resp = NULL;
		}
	}
	return ret;
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{
	int qret;
	int ret;
	int argi;
	char *ep;
	const char *dir = NULL;
	const char *fake_suite = NULL;
	const char *nodata = NULL;
	const char *cmsg = NULL;
	const char *rmsg = NULL;
	int cpad = PROMPT_ACCESSIBLE_PAD;
	char *questions;
	const char *user;
	char *response = NULL;
	char fmt[512];
#ifndef _OPENPAM
	struct pam_conv *conv;
	struct pam_message msg;
	const struct pam_message *msgp;
	struct pam_response *resp;
	int pam_err;
#endif
	(void)flags;
	(void)argc;
	(void)argv;

	pam_get_item(pamh, PAM_USER, (const void **)&user);

	openlog(LOG_NAME, 0, LOG_AUTHPRIV);

	/* Get options */
#ifndef _OPENPAM
	pam_err = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
	if (pam_err != PAM_SUCCESS) {
		return (PAM_SYSTEM_ERR);
	}
	msg.msg_style = PAM_PROMPT_ECHO_OFF;
	msg.msg = password_prompt;
	msgp = &msg;
	for (argi = 0; argi < argc; argi++) {
		if (strlen(argv[argi]) < 6) {
			continue;
		} else if (0 == strncmp(argv[argi], "fake_prompt=", 12)) {
			rmsg = argv[argi] + 12;
		} else if (0 == strncmp(argv[argi], "dir=", 4)) {
			rmsg = argv[argi] + 4;
		} else if (0 == strncmp(argv[argi], "nodata=", 7)) {
			rmsg = argv[argi] + 7;
		} else if (0 == strncmp(argv[argi], "cmsg=", 5)) {
			cmsg = argv[argi] + 5;
		} else if (0 == strncmp(argv[argi], "rmsg=", 5)) {
			rmsg = argv[argi] + 5;
		} else if (0 == strncmp(argv[argi], "cpad=", 5)) {
			cpad = strtol(argv[argi] + 5, &ep, 10);
			if (NULL == ep) {
				cpad = PROMPT_ACCESSIBLE_PAD;
			}
		} else {
			syslog(LOG_ERR, "Unknown option", argv[argi]);
		}
	}
#else
	fake_suite = openpam_get_option(pamh, "fake_prompt");
	dir = openpam_get_option(pamh, "dir");
	nodata = openpam_get_option(pamh, "nodata");
	cmsg = openpam_get_option(pamh, "cmsg");
	rmsg = openpam_get_option(pamh, "rmsg");
	cpad_s = openpam_get_option(pamh, "cpad");
	if (NULL != cpad_s) {
		cpad = strtol(argv[argi] + 5, &ep, 10);
		if (NULL == ep) {
			cpad = PROMPT_ACCESSIBLE_PAD;
		}
	}
#endif

	/*
	 * Generate the challenge "question".  If the user doesn't have any
	 * OCRA data, a fake challenge may be generated.
	 *
	 * Valid expected return codes are:
	 * 	PAM_SUCCESS          -	User has OCRA data and a valid challenge
	 * 				was generated.  A valid user response
	 * 				will be expected.
	 * 	PAM_AUTHINFO_UNAVAIL -	User does not have OCRA data and no fake
	 *		 		challenge was generated.  This result
	 *		 		may be modified based on the "nodata"
	 *		 		setting.
	 * 	PAM_NO_MODULE_DATA   -	User does not have OCRA data and a fake
	 * 				challenge was generated.  The ultimate
	 * 				return code after user input will be
	 * 				based on the "nodata" setting.
	 *
	 * 	Any other return code will be returned as-is.
	 */
	syslog(LOG_AUTH, "OCRA challenge for user %s.", user);
	qret = challenge(dir, user, &questions, nodata, fake_suite);

	/* Only continue if there is a user prompt to display */
	if (PAM_SUCCESS != qret && PAM_NO_MODULE_DATA != qret) {
		ret = qret;
		goto end;
	}
	/* Generate the prompt */
	make_prompt(fmt, sizeof(fmt), questions, cmsg, rmsg, cpad);

	if (PAM_SUCCESS != (ret = get_response(pamh, fmt, &response))) {
		goto end;
	}


	if (PAM_SUCCESS != qret) {
		/*
		 * There was no OCRA data, so don't bother checking the
		 * response
		 */
		ret = qret;
	} else {
		ret = verify(dir, user, questions, response);
	}

	free(response);
end:
	closelog();
	return adjust_return(nodata, ret);
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char *argv[])
{
	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;

	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char *argv[])
{
	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;

	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char *argv[])
{
	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;

	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char *argv[])
{
	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;

	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char *argv[])
{
	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;

	return PAM_SUCCESS;
}

#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY(MODULE_NAME);
#endif
