EXTRA_DIST = osmostp-usermanual.adoc \
    osmostp-usermanual-docinfo.xml \
    osmostp-vty-reference.xml \
    regen_doc.sh \
    chapters \
    vty

if BUILD_MANUALS
  ASCIIDOC = osmostp-usermanual.adoc
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.asciidoc.inc
  osmostp-usermanual.pdf: $(srcdir)/chapters/*.adoc
  aoip-mgw-options.pdf: $(srcdir)/aoip-mgw-options.adoc $(srcdir)/mgw/*.msc

  VTY_REFERENCE = osmostp-vty-reference.xml

  BUILT_REFERENCE_XML = $(builddir)/vty/osmo-stp_vty_reference.xml
  $(builddir)/vty/osmo-stp_vty_reference.xml: $(top_builddir)/stp/osmo-stp
	mkdir -p $(builddir)/vty
	$(top_builddir)/stp/osmo-stp --vty-ref-xml > $@

  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.vty-reference.inc

  OSMO_REPOSITORY=osmo-stp
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.common.inc
endif
