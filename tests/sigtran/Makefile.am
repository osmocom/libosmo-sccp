AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS)

noinst_HEADERS = sua_test_common.h
noinst_PROGRAMS = sua_server_test sua_client_test

sua_server_test_SOURCES = sua_server_test.c sua_test_common.c
sua_server_test_LDADD = $(top_builddir)/src/libosmo-sigtran.la $(LIBOSMOCORE_LIBS) $(TALLOC_LIBS)

sua_client_test_SOURCES = sua_client_test.c sua_test_common.c
sua_client_test_LDADD = $(top_builddir)/src/libosmo-sigtran.la $(LIBOSMOCORE_LIBS) $(TALLOC_LIBS)
