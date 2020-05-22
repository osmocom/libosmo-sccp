AUTOMAKE_OPTIONS = foreign dist-bzip2 1.6

AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include
SUBDIRS = include src tests examples stp doc contrib

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libosmo-sccp.pc libosmo-mtp.pc libosmo-sigtran.pc libosmo-xua.pc

EXTRA_DIST = \
	     .version \
	     contrib/libosmo-sccp.spec.in \
	     debian \
	     git-version-gen \
	     osmoappdesc.py \
	     $(NULL)

AM_DISTCHECK_CONFIGURE_FLAGS = \
  --with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)

@RELMAKE@

BUILT_SOURCES = $(top_srcdir)/.version
$(top_srcdir)/.version:
	echo $(VERSION) > $@-t && mv $@-t $@
dist-hook:
	echo $(VERSION) > $(distdir)/.tarball-version


if HAVE_DOXYGEN

html_DATA = $(top_builddir)/doc/html.tar

doc: $(html_DATA)

$(html_DATA): $(top_builddir)/doc/sigtran/html/index.html
	cd $(top_builddir)/doc && tar cf html.tar */html

$(top_builddir)/doc/sigtran/html/index.html: $(SOURCES) Doxyfile
	@rm -rf doc/sigtran
	mkdir -p doc/sigtran
	$(DOXYGEN) Doxyfile

install-data-hook:
	cd $(DESTDIR)$(htmldir) && tar xf html.tar && rm -f html.tar

uninstall-hook:
	cd $(DESTDIR)$(htmldir) && rm -rf sigtran

DX_CLEAN = doc/sigtran/html/search/* doc/sigtran/{html,latex}/* doc/html.tar doc/doxygen_sqlite3.db doc/sigtran/doxygen_sqlite3.db doc/*.tag

endif

MOSTLYCLEANFILES = $(DX_CLEAN)
