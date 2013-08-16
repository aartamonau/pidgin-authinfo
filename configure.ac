AC_PREREQ([2.69])

AC_INIT([pidgin-authinfo], [0.1],
        [https://github.com/aartamonau/pidgin-authinfo/issues])
AM_INIT_AUTOMAKE([subdir-objects foreign])
LT_INIT([shared disable-static])

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADERS([config.h])

AC_PROG_CC_C99

if test "x${ac_cv_prog_cc_c99}" = xno; then
   AC_MSG_ERROR([A compiler supporting c99 is required])
fi

AC_CHECK_DECL([__GNUC__], [GCC=yes], [GCC=no])
AM_CONDITIONAL([GCC], [test x$GCC = xyes])

PKG_PROG_PKG_CONFIG
PKG_CHECK_MODULES([PIDGIN_AUTHINFO], [purple >= 2.7.0 authinfo >= 0.1])

AC_ARG_WITH(purple-plugin-dir,
            AS_HELP_STRING([--with-purple-plugin-dir=DIR],
                           [Directory for Purple plugins]))

if test -z "$with_purple_plugin_dir"; then
   with_purple_plugin_dir=$($PKG_CONFIG --variable=plugindir \
                                        --define-variable=libdir=$libdir purple)
fi

if test -z "$with_purple_plugin_dir"; then
   AC_MSG_ERROR([Could not detect Purple plugins directory])
fi

AC_SUBST([plugindir], [$with_purple_plugin_dir])

echo "PIDGIN_AUTHINFO_LIBS: ${PIDGIN_AUTHINFO_LIBS}"

AC_OUTPUT
