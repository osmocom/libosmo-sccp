AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall -g $(LIBOSMOCORE_CFLAGS) $(LIBOSMOVTY_CFLAGS) $(LIBOSMONETIF_CFLAGS) $(COVERAGE_CFLAGS)
AM_LDFLAGS=$(COVERAGE_LDFLAGS)

bin_PROGRAMS = osmo-stp

osmo_stp_SOURCES = stp_main.c
osmo_stp_LDADD = $(top_builddir)/src/libosmo-sigtran.la \
		   $(LIBOSMOCORE_LIBS) $(LIBOSMOVTY_LIBS)
