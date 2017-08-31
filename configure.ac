dnl Process this file with autoconf to produce a configure script.
AC_INIT([pam_ocra], [1.4])
AC_CONFIG_AUX_DIR([autotools])
AC_CONFIG_MACRO_DIR([autotools/m4])
m4_include([autotools/common.ac])

# GLOBAL include path
GLOBAL_INCLUDE="-I${srcdir}/include"
AC_SUBST([GLOBAL_INCLUDE])

# libssl include path
AC_ARG_WITH([libssl-include],
    [AC_HELP_STRING([--with-libssl-include=INCLUDE_PATH],
                    [path to libssl headers])],
    [LIBSSL_INCLUDE="-I$withval"],
    [LIBSSL_INCLUDE=''])

AC_SUBST([LIBSSL_INCLUDE])

# libssl library path
AC_ARG_WITH([libssl-lib],
    [AC_HELP_STRING([--with-libssl-lib=LIB_PATH],
                    [path to libssl libraries])],
    [LIBSSL_LIB="-L$withval "'-lssl -lcrypto'],
    [LIBSSL_LIB='-lssl -lcrypto'])

AC_SUBST([LIBSSL_LIB])

dnl define build info
AC_DEFINE_UNQUOTED(FEATURES, "$FEATURES", [Build info, do not touch])

dnl create the makefiles
AC_OUTPUT(Makefile)

dnl print results
AC_MSG_RESULT([*])
AC_MSG_RESULT([* $PACKAGE version $VERSION configured successfully.])
AC_MSG_RESULT([*])
AC_MSG_RESULT([* PREFIX: $prefix])
AC_MSG_RESULT([* FEATURES: $FEATURES])
AC_MSG_RESULT([* CXXFLAGS: $CXXFLAGS])
AC_MSG_RESULT([* LDFLAGS: $LDFLAGS])
AC_MSG_RESULT([* LIBS: $LIBS $boost_thread_LIB])
AC_MSG_RESULT([* OS: $OSTYPE])
AC_MSG_RESULT([*])
