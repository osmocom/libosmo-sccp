AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall -ggdb3 $(LIBOSMOCORE_CFLAGS)

EXTRA_DIST = sccp_test.ok

noinst_PROGRAMS = sccp_test

sccp_test_SOURCES = sccp_test.c $(top_srcdir)/src/sccp.c
sccp_test_LDADD = $(LIBOSMOCORE_LIBS)

