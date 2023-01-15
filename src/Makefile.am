EXTRA_DIST =

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

bin_PROGRAMS = \
	fsmanifest
#rootbin_PROGRAMS =
#rootsbin_DATA 	 = #Create directory
#man_MANS	 =

fsmanifest_LDADD =
fsmanifest_LDFLAGS = $(AM_LDFLAGS)
fsmanifest_CFLAGS = \
	$(AM_CFLAGS)
if WITH_OPENSSL
fsmanifest_LDADD += $(OPENSSL_MODULE_LIBS)
fsmanifest_CFLAGS += $(OPENSSL_MODULE_CFLAGS)
endif
fsmanifest_SOURCES = \
	fsmanifest.c
