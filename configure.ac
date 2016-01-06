dnl Process this file with autoconf to produce a configure script
AC_INIT([libosmo-sccp],
	m4_esyscmd([./git-version-gen .tarball-version]),
	[openbsc@lists.osmocom.org])

AM_INIT_AUTOMAKE([dist-bzip2])
AC_CONFIG_TESTDIR(tests)

dnl kernel style compile messages
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

dnl checks for programs
AC_PROG_MAKE_SET
AC_PROG_CC
AC_PROG_INSTALL
LT_INIT
AC_PROG_LIBTOOL

PKG_CHECK_MODULES(LIBOSMOCORE, libosmocore >= 0.3.0)
PKG_CHECK_MODULES(LIBOSMONETIF, libosmo-netif >= 0.0.6)

# The following test is taken from WebKit's webkit.m4
saved_CFLAGS="$CFLAGS"
CFLAGS="$CFLAGS -fvisibility=hidden "
AC_MSG_CHECKING([if ${CC} supports -fvisibility=hidden])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([char foo;])],
      [ AC_MSG_RESULT([yes])
        SYMBOL_VISIBILITY="-fvisibility=hidden"],
        AC_MSG_RESULT([no]))
CFLAGS="$saved_CFLAGS"
AC_SUBST(SYMBOL_VISIBILITY)

AC_OUTPUT(
    libosmo-sigtran.pc
    libosmo-sccp.pc
    libosmo-mtp.pc
    include/sccp/Makefile
    include/mtp/Makefile
    include/osmocom/Makefile
    include/osmocom/sigtran/Makefile
    include/Makefile
    src/Makefile
    tests/Makefile
    tests/sccp/Makefile
    tests/mtp/Makefile
    tests/m2ua/Makefile
    tests/sigtran/Makefile
    Makefile)

