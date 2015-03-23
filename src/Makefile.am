AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS)

sccpdir = $(libdir)
sccp_LIBRARIES = libsccp.a libmtp.a libxua.a

libsccp_a_SOURCES = sccp.c
libmtp_a_SOURCES = mtp_pcap.c 
libxua_a_SOURCES = xua_msg.c
