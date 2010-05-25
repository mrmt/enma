# $Id: configure.ac 504 2008-08-27 08:31:59Z takahiko $

AC_INIT(enma, 1.0.0)
AC_CONFIG_SRCDIR(enma/src/enma.c)

AC_PROG_CC
AC_PROG_CPP
AC_PROG_MAKE_SET
AC_PROG_INSTALL
AC_PROG_RANLIB

AC_CHECK_HEADERS(sys/prctl.h net/if_dl.h)
AC_CHECK_FUNCS(prctl)

AC_SEARCH_LIBS(socket, socket)
AC_SEARCH_LIBS(clock_gettime, rt)

dnl libbind built on Solaris 8 or later depends libmd5
AC_SEARCH_LIBS(MD5Init, md5)

AC_REPLACE_FUNCS(strlcpy)

AC_ARG_ENABLE(debug,
	AC_HELP_STRING(--enable-debug, [enable debugging]),
	[CFLAGS="$CFLAGS -g3 -O0"],
	[CFLAGS="$CFLAGS -g -O2"])

AC_ARG_WITH(libmilter-libdir,
	AC_HELP_STRING(--with-libmilter-libdir=DIR, [specify where to find libmilter library]),
	[LDFLAGS="$LDFLAGS -L$withval"])

AC_ARG_WITH(libmilter-incdir,
	AC_HELP_STRING(--with-libmilter-incdir=DIR, [specify where to find libmilter header files]),
	[CPPFLAGS="$CPPFLAGS -I$withval"])

AC_ARG_WITH(libmilter,
	AC_HELP_STRING(--with-libmilter=DIR, [specify libmilter base directory]),
	[CPPFLAGS="$CPPFLAGS -I$withval/include" LDFLAGS="$LDFLAGS -L$withval/lib"],
	[CPPFLAGS="$CPPFLAGS -I/usr/local/include" LDFLAGS="$LDFLAGS -L/usr/local/lib"])

AC_ARG_WITH(libbind-libdir,
	AC_HELP_STRING(--with-libbind-libdir=DIR, [specify where to find libbind library]),
	[LDFLAGS="$LDFLAGS -L$withval"])

AC_ARG_WITH(libbind-incdir,
	AC_HELP_STRING(--with-libbind-incdir=DIR, [specify where to find libbind header files]),
	[CPPFLAGS="$CPPFLAGS -I$withval"])

AC_ARG_WITH(libbind,
	AC_HELP_STRING(--with-libbind=DIR, [specify libbind base directory]),
	[CPPFLAGS="$CPPFLAGS -I$withval/bind/include" LDFLAGS="$LDFLAGS -L$withval/lib"],
	[CPPFLAGS="$CPPFLAGS -I/usr/local/bind/include" LDFLAGS="$LDFLAGS -L$/usr/local/lib"])

CFLAGS="$CFLAGS -std=gnu99 -Wall -Wextra"
CPPFLAGS="$CPPFLAGS -I$includedir -D_REENTRANT -D_POSIX_PTHREAD_SEMANTICS"
LDFLAGS="$LDFLAGS -L$libdir -lpthread"

AC_CHECK_LIB(bind, __res_ndestroy,
	[true],     dnl skip default action 
	[AC_MSG_ERROR(libbind not found)])

AC_CHECK_LIB(milter, smfi_main,
	[true],     dnl skip default action
	[AC_MSG_ERROR(libmilter not found)], [-lbind])

AC_CONFIG_HEADERS(config.h)
AC_CONFIG_FILES(Makefile libsidf/Makefile libsidf/src/Makefile enma/Makefile)
AC_CONFIG_FILES(enma/src/Makefile enma/bin/Makefile enma/etc/Makefile enma/man/Makefile)

AC_OUTPUT
