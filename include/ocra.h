#pragma once

int challenge(
	const char *path,
	const char *user_id,
	char **questions,
	const char *nodata,
	const char *fake_suite);

int verify(
	const char *path,
	const char *user_id,
	const char *questions,
	const char *response);

int find_counter(
	const char *path,
	const char *questions,
	const char *response1,
	const char *response2);

