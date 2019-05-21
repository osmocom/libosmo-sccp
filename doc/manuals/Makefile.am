EXTRA_DIST = osmostp-usermanual.adoc \
    osmostp-usermanual-docinfo.xml \
    osmostp-vty-reference.xml \
    chapters \
    vty

if BUILD_MANUALS
  ASCIIDOC = osmostp-usermanual.adoc
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.asciidoc.inc
  osmostp-usermanual.pdf: $(srcdir)/chapters/*.adoc
  aoip-mgw-options.pdf: $(srcdir)/aoip-mgw-options.adoc $(srcdir)/mgw/*.msc

  VTY_REFERENCE = osmostp-vty-reference.xml
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.vty-reference.inc

  OSMO_REPOSITORY=osmo-stp
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.common.inc
endif
