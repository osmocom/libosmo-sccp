AUTOMAKE_OPTIONS = foreign dist-bzip2 1.6

AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include
SUBDIRS = include src tests examples stp

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libosmo-sccp.pc libosmo-mtp.pc libosmo-sigtran.pc libosmo-xua.pc

EXTRA_DIST = .version doc/examples/osmo-stp.cfg

BUILT_SOURCES = $(top_srcdir)/.version
$(top_srcdir)/.version:
	echo $(VERSION) > $@-t && mv $@-t $@
dist-hook:
	echo $(VERSION) > $(distdir)/.tarball-version
