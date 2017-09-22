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

#include <ldap_storage_intern.h>
#include <sys/param.h>


#define DB_OPEN_FLAGS_RO DB_RDONLY
#define DB_OPEN_FLAGS_RW 0
#define DB_OPEN_FLAGS_CREATE DB_CREATE

/*
 * DB type for transparent use as db_storage replacement.
 */
typedef struct DB_t {
    int (*open)();
    int (*close)();
    int (*put)();
    int (*get)();
    int (*sync)();
    ldap_session_t* session;
} DB;

typedef struct DBT_t {;
    char *data;
    size_t size;
} DBT;

int
config_db_get(DB * db, DBT * K, DBT * V);

int
config_db_put(DB * db, DBT * K, DBT * V);

int
config_db_close(DB * db);

int
config_db_open(DB ** db, int flags, const char * path, const int user_id,
    const char * nodata, const char * fake_suite);

int
config_db_sync(DB * db);
