AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS)

sccpdir = $(libdir)
sccp_LIBRARIES = libsccp.a libmtp.a libm2ua.a

libsccp_a_SOURCES = sccp.c
libmtp_a_SOURCES = mtp_pcap.c 
libm2ua_a_SOURCES = m2ua_msg.c
