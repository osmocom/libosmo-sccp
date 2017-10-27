dnl Process this file with autoconf to produce a configure script
AC_INIT([libosmo-sccp],
	m4_esyscmd([./git-version-gen .tarball-version]),
	[openbsc@lists.osmocom.org])

dnl *This* is the root dir, even if an install-sh exists in ../ or ../../
AC_CONFIG_AUX_DIR([.])

AM_INIT_AUTOMAKE([dist-bzip2])
AC_CONFIG_TESTDIR(tests)

dnl kernel style compile messages
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

dnl include release helper
RELMAKE='-include osmo-release.mk'
AC_SUBST([RELMAKE])

dnl checks for programs
AC_PROG_MAKE_SET
AC_PROG_CC
AC_PROG_INSTALL
LT_INIT
AC_PROG_LIBTOOL

dnl check for pkg-config (explained in detail in libosmocore/configure.ac)
AC_PATH_PROG(PKG_CONFIG_INSTALLED, pkg-config, no)
if test "x$PKG_CONFIG_INSTALLED" = "xno"; then
        AC_MSG_WARN([You need to install pkg-config])
fi
PKG_PROG_PKG_CONFIG([0.20])

PKG_CHECK_MODULES(LIBOSMOCORE, libosmocore >= 0.10.0)
PKG_CHECK_MODULES(LIBOSMOVTY, libosmovty >= 0.10.0)
PKG_CHECK_MODULES(LIBOSMONETIF, libosmo-netif >= 0.1.0)
PKG_CHECK_MODULES(LIBOSMOGSM, libosmogsm >= 0.10.0)

old_LIBS=$LIBS
AC_SEARCH_LIBS([sctp_send], [sctp], [
	AC_DEFINE(HAVE_LIBSCTP, 1, [Define 1 to enable SCTP support])
	AC_SUBST(HAVE_LIBSCTP, [1])
	if test -n "$ac_lib"; then
		AC_SUBST(LIBSCTP_LIBS, [-l$ac_lib])
	fi
	], [
	AC_MSG_ERROR([sctp_send not found in searched libs])])
LIBS=$old_LIBS

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

CFLAGS="$CFLAGS -Wall"
CPPFLAGS="$CPPFLAGS -Wall"

AC_ARG_ENABLE(doxygen,
	[AS_HELP_STRING(
		[--disable-doxygen],
		[Disable generation of documentation using doxygen],
	)],
	[doxygen=$enableval], [doxygen="yes"])
AC_PATH_PROG(DOXYGEN,doxygen,false)
AM_CONDITIONAL(HAVE_DOXYGEN, test $DOXYGEN != false && test "x$doxygen" = "xyes")

AC_OUTPUT(
    libosmo-sigtran.pc
    libosmo-sccp.pc
    libosmo-mtp.pc
    libosmo-xua.pc
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
    tests/xua/Makefile
    tests/ss7/Makefile
    examples/Makefile
    stp/Makefile
    Doxyfile
    Makefile)
