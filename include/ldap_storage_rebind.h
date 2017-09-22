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

/* rebind_proc declaration for different ldap implementations */
int rebind_proc(LDAP * ld,
#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)
#if LDAP_SET_REBIND_PROC_ARGS == 3
    LDAP_CONST char *url, ber_tag_t request, ber_int_t msgid, void *arg
#else /* LDAP_SET_REBIND_PROC_ARGS == 3 */
    LDAP_CONST char *url, int request, ber_int_t msgid
#endif /* else LDAP_SET_REBIND_PROC_ARGS == 3 */
#else /* (LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000) */
#if LDAP_SET_REBIND_PROC_ARGS == 3
    char **whop, char **credp, int *methodp, int freeit, void *arg
#else /* LDAP_SET_REBIND_PROC_ARGS == 3 */
    char **whop, char **credp, int *methodp, int freeit
#endif /* else LDAP_SET_REBIND_PROC_ARGS == 3 */
#endif /* else (LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000) */
);
