AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBOSMOVTY_CFLAGS) \
		$(LIBOSMONETIF_CFLAGS)

noinst_HEADERS = \
	sccp_internal.h \
	ss7_internal.h \
	xua_asp_fsm.h \
	xua_as_fsm.h \
	xua_internal.h \
	$(NULL)

noinst_LIBRARIES = libxua.a

libxua_a_SOURCES = xua_msg.c
# ensure that the file for the static lib is built with different C
# flags, working around automake complaining that xua_msg.o is built
# both with libtool (below) and without (here)
libxua_a_CPPFLAGS = $(AM_CPPFLAGS) -DDUMMY -UDUMMY

lib_LTLIBRARIES = libosmo-sigtran.la

# This is _NOT_ the library release version, it's an API version.
# Please read Chapter 6 "Library interface versions" of the libtool
# documentation before making any modification
LIBVERSION=10:0:0

libosmo_sigtran_la_SOURCES = \
	ipa.c \
	m3ua.c \
	osmo_ss7.c \
	osmo_ss7_as.c \
	osmo_ss7_asp.c \
	osmo_ss7_asp_peer.c \
	osmo_ss7_hmrt.c \
	osmo_ss7_vty.c \
	osmo_ss7_xua_srv.c \
	sccp2sua.c \
	sccp_helpers.c \
	sccp_lbcs.c \
	sccp_sap.c \
	sccp_sclc.c \
	sccp_scmg.c \
	sccp_scrc.c \
	sccp_scoc.c \
	sccp_types.c \
	sccp_user.c \
	sccp_vty.c \
	sua.c \
	xua_asp_fsm.c \
	xua_as_fsm.c \
	xua_default_lm_fsm.c \
	xua_msg.c \
	xua_rkm.c \
	xua_shared.c \
	xua_snm.c \
	$(NULL)

libosmo_sigtran_la_LDFLAGS = -version-info $(LIBVERSION) -no-undefined -export-symbols-regex '^osmo_'
libosmo_sigtran_la_LIBADD = \
	$(LIBOSMONETIF_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBOSMOCORE_LIBS) \
	$(LIBSCTP_LIBS) \
	$(NULL)
