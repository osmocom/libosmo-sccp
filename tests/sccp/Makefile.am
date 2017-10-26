AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall -ggdb3 $(LIBOSMOCORE_CFLAGS)
AM_CFLAGS+=$(LIBOSMONETIF_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBSCTP_CFLAGS) $(LIBOSMOVTY_CFLAGS)

EXTRA_DIST = sccp_test.ok

noinst_PROGRAMS = \
	sccp_test \
	ni_test \
	$(NULL)

sccp_test_SOURCES = sccp_test.c
sccp_test_LDADD = \
	$(LIBOSMOCORE_LIBS) \
	$(top_builddir)/src/sccp.o \
	$(NULL)

ni_test_SOURCES = \
	ni_test.c \
	$(top_srcdir)/src/m3ua.c \
	$(top_srcdir)/src/xua_msg.c \
	$(top_srcdir)/src/sccp_helpers.c \
	$(top_srcdir)/src/osmo_ss7.c \
	$(top_srcdir)/src/sccp_scrc.c \
	$(top_srcdir)/src/sccp_user.c \
	$(top_srcdir)/src/xua_rkm.c \
	$(top_srcdir)/src/xua_asp_fsm.c \
	$(top_srcdir)/src/osmo_ss7_hmrt.c \
	$(top_srcdir)/src/sua.c \
	$(top_srcdir)/src/sccp_sap.c \
	$(top_srcdir)/src/sccp_scoc.c \
	$(top_srcdir)/src/ipa.c \
	$(top_srcdir)/src/xua_as_fsm.c \
	$(top_srcdir)/src/xua_default_lm_fsm.c \
	$(top_srcdir)/src/sccp_sclc.c \
	$(top_srcdir)/src/sccp2sua.c \
	$(NULL)

ni_test_CFLAGS = \
	-I$(top_srcdir)/src \
	$(NULL)

ni_test_LDFLAGS = \
	-Wl,--wrap=m3ua_tx_xua_as \
	$(NULL)

ni_test_LDADD = \
	$(top_builddir)/src/libxua.a \
	$(top_builddir)/src/libsccp.a \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBOSMONETIF_LIBS) \
	$(LIBSCTP_LIBS) \
	$(NULL)
