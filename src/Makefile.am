AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMONETIF_CFLAGS)

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
LIBVERSION=0:0:0

libosmo_sigtran_la_SOURCES = sccp_sap.c sua.c xua_msg.c
libosmo_sigtran_la_LDFLAGS = -version-info $(LIBVERSION) -no-undefined -export-symbols-regex '^osmo_'
libosmo_sigtran_la_LIBADD = $(LIBOSMOCORE_LIBS) $(LIBOSMONETIF_LIBS) $(LIBSCTP_LIBS)
