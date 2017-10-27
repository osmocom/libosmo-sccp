AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include -Wall
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOVTY_CFLAGS)

AM_LDFLAGS = -static
LDADD = $(top_builddir)/src/libosmo-sigtran.la \
	$(LIBOSMOCORE_LIBS) $(LIBOSMOVTY_LIBS) $(LIBOSMONETIF_LIBS) $(LIBSCTP_LIBS)

EXTRA_DIST = xua_test.ok xua_test.err

noinst_HEADERS = sccp_test_data.h
noinst_PROGRAMS = xua_test

xua_test_SOURCES = xua_test.c sccp_test_data.c
