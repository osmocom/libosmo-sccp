AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall -ggdb3 $(LIBOSMOCORE_CFLAGS)
AM_LDFLAGS = -no-install

EXTRA_DIST = sccp_test.ok

check_PROGRAMS = sccp_test

sccp_test_SOURCES = sccp_test.c
sccp_test_LDADD = \
	$(LIBOSMOCORE_LIBS) \
	$(top_builddir)/src/sccp.o \
	$(NULL)

