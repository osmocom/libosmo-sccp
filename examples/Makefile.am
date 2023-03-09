AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall -g $(LIBOSMOCORE_CFLAGS) $(LIBOSMOVTY_CFLAGS) $(LIBOSMONETIF_CFLAGS) $(COVERAGE_CFLAGS)
AM_LDFLAGS=$(COVERAGE_LDFLAGS)

noinst_HEADERS = internal.h

noinst_PROGRAMS = sccp_demo_user

sccp_demo_user_SOURCES = sccp_demo_user.c sccp_test_server.c sccp_test_vty.c
sccp_demo_user_LDADD = $(top_builddir)/src/libosmo-sigtran.la \
		   $(LIBOSMOCORE_LIBS) $(LIBOSMOVTY_LIBS)
