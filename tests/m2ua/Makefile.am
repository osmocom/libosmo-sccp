AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include -Wall
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS)

EXTRA_DIST = m2ua_test.ok

check_PROGRAMS = m2ua_test
m2ua_test_SOURCES = m2ua_test.c
m2ua_test_LDADD = $(top_builddir)/src/libxua.a $(LIBOSMOCORE_LIBS)
