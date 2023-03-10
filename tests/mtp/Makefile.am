AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS = -Wall $(LIBOSMOCORE_CFLAGS)
AM_LDFLAGS = -no-install

check_PROGRAMS = mtp_parse_test

EXTRA_DIST = mtp_parse_test.ok

mtp_parse_test_SOURCES = mtp_parse_test.c
