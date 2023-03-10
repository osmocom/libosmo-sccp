AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOVTY_CFLAGS)

AM_LDFLAGS = -static -no-install
LDADD = $(top_builddir)/src/libosmo-sigtran.la \
	$(LIBOSMOCORE_LIBS) $(LIBOSMOVTY_LIBS) $(LIBOSMONETIF_LIBS) $(LIBSCTP_LIBS)

EXTRA_DIST = ss7_test.ok ss7_test.err

check_PROGRAMS = ss7_test

ss7_test_SOURCES = ss7_test.c
