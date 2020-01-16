AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBOSMOVTY_CFLAGS) \
		$(LIBOSMONETIF_CFLAGS)

noinst_HEADERS = sccp_internal.h xua_asp_fsm.h xua_as_fsm.h xua_internal.h

# Legacy static libs

sccpdir = $(libdir)
sccp_LIBRARIES = libsccp.a libmtp.a libxua.a

libsccp_a_SOURCES = sccp.c
libmtp_a_SOURCES = mtp_pcap.c
libxua_a_SOURCES = xua_msg.c
# ensure that the file for the static lib is built with different C
# flags, working around automake complaining that xua_msg.o is built
# both with libtool (below) and without (here)
libxua_a_CPPFLAGS = $(AM_CPPFLAGS) -DDUMMY -UDUMMY


# New shared lib

lib_LTLIBRARIES = libosmo-sigtran.la

# This is _NOT_ the library release version, it's an API version.
# Please read Chapter 6 "Library interface versions" of the libtool
# documentation before making any modification
LIBVERSION=5:0:0

libosmo_sigtran_la_SOURCES = sccp_sap.c sua.c m3ua.c xua_msg.c sccp_helpers.c \
			     sccp2sua.c sccp_scrc.c sccp_sclc.c sccp_scoc.c \
			     sccp_user.c sccp_types.c xua_rkm.c xua_default_lm_fsm.c \
			     osmo_ss7.c osmo_ss7_hmrt.c xua_asp_fsm.c xua_as_fsm.c \
			     osmo_ss7_vty.c sccp_vty.c ipa.c
libosmo_sigtran_la_LDFLAGS = -version-info $(LIBVERSION) -no-undefined -export-symbols-regex '^osmo_'
libosmo_sigtran_la_LIBADD = $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS) $(LIBOSMOVTY_LIBS) \
			    $(LIBOSMONETIF_LIBS) $(LIBSCTP_LIBS)
