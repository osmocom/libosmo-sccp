AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include -Wall
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOVTY_CFLAGS)

AM_LDFLAGS = -static
LDADD = $(top_builddir)/src/libosmo-sigtran.la \
	$(LIBOSMOCORE_LIBS) $(LIBOSMOVTY_LIBS) $(LIBOSMONETIF_LIBS) $(LIBSCTP_LIBS)

EXTRA_DIST = \
	ss7_asp_test.vty \
	vty_test_runner.py \
	$(NULL)

check_PROGRAMS = ss7_asp_vty_test

ss7_asp_vty_test_SOURCES = ss7_asp_vty_test.c

if ENABLE_EXT_TESTS
ext-tests:
	$(MAKE) vty-test
else
ext-tests:
	echo "Not running python-based external tests (determined at configure-time)"
endif

vty-python-test: $(BUILT_SOURCES)
	$(srcdir)/vty_test_runner.py -w $(abs_top_builddir) -v

# To update the VTY script from current application behavior,
# pass -u to osmo_verify_transcript_vty.py by doing:
#   make vty-test U=-u
vty-transcript-test: ss7_asp_vty_test
	osmo_verify_transcript_vty.py -v \
		-p 42043 \
		-r "$(builddir)/ss7_asp_vty_test" \
		$(U) $(srcdir)/ss7_asp_*.vty

# don't run multiple tests concurrently so that the ports don't conflict
vty-test:
	$(MAKE) vty-python-test
	$(MAKE) vty-transcript-test

check-local:
	$(MAKE) $(AM_MAKEFLAGS) ext-tests
