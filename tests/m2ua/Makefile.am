INCLUDES = $(all_includes) -I$(top_srcdir)/include -Wall
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS)

noinst_PROGRAMS = m2ua_test
m2ua_test_SOURCES = m2ua_test.c
m2ua_test_LDADD = $(LIBOSMOCORE_LIBS) $(top_builddir)/src/libm2ua.a
