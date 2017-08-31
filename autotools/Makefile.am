## Project pam_ocra
lib_LTLIBRARIES += libpam_ocra.la
libpam_ocra_la_CXXFLAGS = $(pam_ocra_CXXFLAGS)
libpam_ocra_la_LDFLAGS  = $(pam_ocra_LDFLAGS)
libpam_ocra_la_LIBADD   = $(pam_ocra_LIBS)
libpam_ocra_la_DEPENDENCIES = $(pam_ocra_DEPENDS)
libpam_ocra_la_SOURCES = src/ocra.c
libpam_ocra_la_SOURCES += src/pam_ocra.c
libpam_ocra_la_SOURCES += src/db_storage.c
libpam_ocra_la_SOURCES += src/rfc6287.c
libpam_ocra_include_HEADERS = include/rfc6287.h

bin_PROGRAMS += rfc6287_test
rfc6287_test_CXXFLAGS = $(pam_ocra_CXXFLAGS)
rfc6287_test_LDFLAGS  = $(pam_ocra_LDFLAGS)
rfc6287_test_LDADD    = libpam_ocra.la $(pam_ocra_LIBS)
rfc6287_test_DEPENDENCIES = libpam_ocra.la $(pam_ocra_DEPENDS)
rfc6287_test_SOURCES = test/rfc6287_test.c

bin_PROGRAMS += ocra_tool
ocra_tool_CXXFLAGS = $(pam_ocra_CXXFLAGS)
ocra_tool_LDFLAGS  = $(pam_ocra_LDFLAGS)
ocra_tool_LDADD    = libpam_ocra.la $(pam_ocra_LIBS)
ocra_tool_DEPENDENCIES = libpam_ocra.la $(pam_ocra_DEPENDS)
ocra_tool_SOURCES = src/ocra_tool.c
