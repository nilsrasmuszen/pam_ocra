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

#include <sys/types.h>
#include <pwd.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <fcntl.h>
#include <syslog.h>
#include <err.h>
#include <errno.h>
#include <sysexits.h>

#include <security/pam_appl.h>

#include <openssl/evp.h>

#include <db_storage.h>

int
config_db_close(DB * db){
	int r;

	if (0 != (r = db->close(db, 0))){
		syslog(LOG_ERR, "db->close() failed: %s", strerror(errno));
	}
	return r;
}

int
config_db_get(DB * db, DBT * K, DBT * V)
{
	int r;

	if (0 != (r = db->get(db, NULL, K, V, 0))){
		syslog(LOG_ERR, "db->get() failed for %s :%s",
		    (const char *)(K->data),
		    (1 == r) ? "key not in db" : (strerror(errno)));
	}
	return r;
};

int
config_db_open(DB ** db, int flags, const char *path, const int user_id,
    const char *nodata, const char *fake_suite)
{
	int r = 0;
	struct passwd *pwd = NULL;
	char *p1, *p2;
	char *ep = NULL;

	if (0 != db_create(db, NULL, 0)) {
		syslog(LOG_ERR, "db_create failed: %s", strerror(errno));
		return 1;
	}
	
	if (path != NULL) {
		/**
		 * Open by path.
		 */
		if (0 != ((*db)->open(*db, NULL, path, NULL, DB_BTREE, flags, 0600))) {
			syslog(LOG_ERR, "Open configuration from path (%s) failed. %s", path, strerror(errno));
			(*db)->close(*db, 0);
			return 1;
		}
		return 0;
	}
	/**
	 * Open by user_id
	 */

	if (NULL == (pwd = getpwuid(user_id))) {
		syslog(LOG_ERR, "getpwuid failed: %s", strerror(errno));
		(*db)->close(*db, 0);
		return 1;
	}

	asprintf(&p1, "%s/.ocra", pwd->pw_dir);
	if (0 != ((*db)->open(*db, NULL, p1, NULL, DB_BTREE, flags, 0600))) {
		syslog(LOG_ERR, "Open configuration for user path (%s) failed. %s", p1, strerror(errno));
		(*db)->close(*db, 0);
		return 1;
	}
	return 0;
}

int
config_db_put(DB * db, DBT * K, DBT * V){
	int r;

	if (0 != (r = db->put(db, NULL, K, V, 0))){
		syslog(LOG_ERR, "db->put() failed for %s: %s",
		    (const char *)(K->data),
		    strerror(errno));
	}
	return r;
}

int
config_db_sync(DB * db){
	int r;

	if (0 != (r = (db->sync(db, 0)))){
		err(EX_OSERR, "db->sync() failed");
	}
	return r;
}
