dnl Process this file with autoconf to produce a configure script.
AC_INIT([pam_ocra], [1.4])

AM_CONFIG_HEADER(include/config.h)
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

AC_ARG_ENABLE(ldap, [  --enable-ldap         enable ldap for key and pin storage
[[default=no]]],[
  if test "$enableval" = no; then
    ac_use_ldap=no
  else
    ac_use_ldap=yes
  fi
  ],[ ac_use_ldap=no ])

dnl Only build ldap related code (and not berkley) when LDAP is enabled
AM_CONDITIONAL([USE_LDAP], [test "$ac_use_ldap" == "yes"])

AC_ARG_WITH(ldap-lib,
    [  --with-ldap-lib=type    select ldap library [auto|netscape5|netscape4|netscape3|umich|openldap]])
AC_ARG_WITH(ldap-dir,
    [  --with-ldap-dir=DIR     base directory of ldap SDK])
AC_ARG_WITH(ldap-conf-file,
    [  --with-ldap-conf-file     path to LDAP configuration file],
    [AC_DEFINE_UNQUOTED(PAM_LDAP_PATH_CONF, "$with_ldap_conf_file")])
AC_ARG_WITH(ldap-secret-file,
    [  --with-ldap-secret-file   path to LDAP root secret file],
    [AC_DEFINE_UNQUOTED(PAM_LDAP_PATH_ROOTPASSWD, "$with_ldap_secret_file")])

dnl define build info
AC_DEFINE_UNQUOTED(FEATURES, "$FEATURES", [Build info, do not touch])
AC_CHECK_HEADERS(security/pam_appl.h security/pam_misc.h security/pam_modules.h)
AC_CHECK_HEADERS(pam/pam_appl.h pam/pam_misc.h pam/pam_modules.h)
AC_CHECK_LIB(pam, main)
AC_CHECK_LIB(pamc, main)
AC_CHECK_LIB(ssl, main)

if test "$ac_use_ldap" == "yes"; then
    AC_SUBST(pam_ldap_so_LD)
    AC_SUBST(pam_ldap_so_LDFLAGS)
    AC_CHECK_HEADERS(des.h crypt.h)
    AC_CHECK_HEADERS(lber.h)
    AC_CHECK_HEADERS(ldap.h, , AC_MSG_ERROR(could not locate <ldap.h>))
    AC_CHECK_HEADERS(ldap_ssl.h)
    AC_CHECK_HEADERS(sasl/sasl.h)
    AC_CHECK_HEADERS(sasl.h)
    AC_CHECK_LIB(dl, main)
    AC_CHECK_LIB(resolv, main)
    AC_CHECK_LIB(crypt, main)
    AC_CHECK_LIB(crypto, main)
    AC_CHECK_LIB(nsl, main)
    AC_CHECK_FUNCS(gethostbyname)
    if test "$ac_cv_func_gethostbyname" = "no"; then
        unset ac_cv_func_gethostbyname
        AC_CHECK_LIB(nsl, main)
        AC_CHECK_FUNCS(gethostbyname)
    fi
    dnl check which ldap library we have
    if test -z "$with_ldap_lib"; then
      with_ldap_lib=auto
    fi
    if test -z "$found_ldap_lib" -a \( $with_ldap_lib = auto -o $with_ldap_lib = umich -o $with_ldap_lib = openldap \); then
        AC_CHECK_LIB(lber, main)
        AC_CHECK_LIB(ldap, main, LIBS="-lldap $LIBS" found_ldap_lib=yes)
    fi

    if test -z "$found_ldap_lib" -a \( $with_ldap_lib = auto -o $with_ldap_lib = netscape5 \); then
        AC_CHECK_LIB(ldap50, main, LIBS="-lldap50 -lssldap50 -lssl3 -lnss3 -lnspr4 -lprldap50 -lplc4 -lplds4 $LIBS" found_ldap_lib=yes need_pthread=yes,, -lpthread)
    fi
    if test -z "$found_ldap_lib" -a \( $with_ldap_lib = auto -o $with_ldap_lib = netscape4 \); then
        AC_CHECK_LIB(ldapssl41, main, LIBS="-lldapssl41 -lplc3 -lplds3 -lnspr3 $LIBS" found_ldap_lib=yes need_pthread=yes,, -lpthread)
        if test -z "$found_ldap_lib"; then
            AC_CHECK_LIB(ldapssl40, main, LIBS="-lldapssl40 $LIBS" found_ldap_lib=yes need_pthread=yes,, -lpthread)
        fi
        if test -z "$found_ldap_lib"; then
            AC_CHECK_LIB(ldap41, main, LIBS="-lldap41 $LIBS" found_ldap_lib=yes need_pthread=no,,)
        fi
        if test -z "$found_ldap_lib"; then
            AC_CHECK_LIB(ldap40, main, LIBS="-lldap40 $LIBS" found_ldap_lib=yes need_pthread=no,,)
        fi
    fi

    if test -z "$found_ldap_lib" -a \( $with_ldap_lib = auto -o $with_ldap_lib = netscape3 \); then
        AC_CHECK_LIB(ldapssl30, main, LIBS="-lldapssl30 $LIBS" found_ldap_lib=yes need_pthread=yes,, -lpthread)
    fi

    if test -z "$found_ldap_lib"; then
        AC_MSG_ERROR(could not locate a valid LDAP library)
    fi

    AC_CHECK_FUNCS(ldap_init ldap_get_lderrno ldap_set_lderrno ldap_parse_result ldap_memfree ldap_controls_free ldap_set_option ldap_get_option)
    if test "$enable_ssl" \!= "no"; then
      AC_CHECK_FUNCS(ldapssl_init ldap_start_tls_s ldap_pvt_tls_set_option)
    fi
    AC_CHECK_FUNCS(ldap_initialize)
    AC_CHECK_FUNCS(ldap_sasl_bind ldap_sasl_interactive_bind_s)
    AC_CHECK_FUNCS(gethostbyname_r)

    if test "$ac_cv_func_gethostbyname_r" = "yes"; then
        AC_CACHE_CHECK(whether gethostbyname_r takes 6 arguments, xad_cv_gethostbyname_r_args, [
        AC_TRY_COMPILE([
    #include <netdb.h>], [gethostbyname_r(0, 0, 0, 0, 0, 0);], [xad_cv_gethostbyname_r_args=6], [
            AC_TRY_COMPILE([
                    #include <netdb.h>],
                    [gethostbyname_r(0, 0, 0, 0, 0);], [xad_cv_gethostbyname_r_args=5], [xad_cv_gethostbyname_r_args=3]
    )]) ])
        AC_DEFINE_UNQUOTED(GETHOSTBYNAME_R_ARGS, $xad_cv_gethostbyname_r_args)
    fi

    AC_CHECK_FUNCS(ldap_set_rebind_proc)
    AC_CACHE_CHECK(whether ldap_set_rebind_proc takes 3 arguments,
        pam_ldap_cv_ldap_set_rebind_proc, [
        AC_TRY_COMPILE([
            #include <lber.h>
            #include <ldap.h>],
            [ldap_set_rebind_proc(0, 0, 0);],
            [pam_ldap_cv_ldap_set_rebind_proc=3],
            [pam_ldap_cv_ldap_set_rebind_proc=2]) ])

    AC_DEFINE_UNQUOTED(LDAP_SET_REBIND_PROC_ARGS, $pam_ldap_cv_ldap_set_rebind_proc)


else
    AC_CHECK_LIB(db, main)
fi


dnl create the makefiles
AC_OUTPUT(Makefile)

dnl print results
AC_MSG_RESULT([*])
AC_MSG_RESULT([* $PACKAGE version $VERSION configured successfully.])
AC_MSG_RESULT([*])
AC_MSG_RESULT([* PREFIX: $prefix])
AC_MSG_RESULT([* FEATURES: $FEATURES])
AC_MSG_RESULT([* LDAP: $ac_use_ldap])
AC_MSG_RESULT([* CXXFLAGS: $CXXFLAGS])
AC_MSG_RESULT([* LDFLAGS: $LDFLAGS])
AC_MSG_RESULT([* LIBS: $LIBS $boost_thread_LIB])
AC_MSG_RESULT([* OS: $OSTYPE])
AC_MSG_RESULT([*])
