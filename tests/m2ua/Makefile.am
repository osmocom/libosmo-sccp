AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS)
AM_LDFLAGS = -no-install

EXTRA_DIST = m2ua_test.ok

check_PROGRAMS = m2ua_test
m2ua_test_SOURCES = m2ua_test.c
m2ua_test_LDADD = $(top_builddir)/src/libxua.a $(LIBOSMOCORE_LIBS)
