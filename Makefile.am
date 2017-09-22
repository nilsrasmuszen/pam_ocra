# Automake definition for aclocal
# This file defines how autotools will use the configure variables and which
# binaries are generated

include autotools/common.am

BUILT_SOURCES=
INCLUDES=@GLOBAL_INCLUDE@ @LIBSSL_INCLUDE@
LIBS=@LIBSSL_LIB@ @LIBS@

pkgconfig_DATA=pam_ocra.pc
dist_DATA_IN+=pam_ocra.pc.in
man_MANS = doc/pam_ocra.8 doc/ocra_tool.8

noinst_LTLIBRARIES=
lib_LTLIBRARIES=
bin_PROGRAMS=

# The definition of the sources is separated
include autotools/Makefile.am

