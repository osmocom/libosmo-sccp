AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall -g $(LIBOSMOCORE_CFLAGS) $(LIBOSMOVTY_CFLAGS) $(LIBOSMONETIF_CFLAGS) $(COVERAGE_FLAGS)
AM_LDFLAGS=$(COVERAGE_LDFLAGS)

noinst_HEADERS = internal.h

noinst_PROGRAMS = m3ua_example

m3ua_example_SOURCES = m3ua_example.c sccp_test_server.c sccp_test_vty.c
m3ua_example_LDADD = $(top_builddir)/src/libosmo-sigtran.la \
		   $(LIBOSMOCORE_LIBS) $(LIBOSMOVTY_LIBS)
