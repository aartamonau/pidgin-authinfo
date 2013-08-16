ACLOCAL_AMFLAGS = -I m4

if GCC
GCC_FLAGS = -Wall -Werror
endif

AM_CFLAGS = $(GCC_FLAGS) $(PIDGIN_AUTHINFO_CFLAGS)
AM_LDFLAGS = $(PIDGIN_AUTHINFO_LIBS)

plugin_LTLIBRARIES = authinfo.la
authinfo_la_SOURCES = src/authinfo.c
authinfo_la_LDFLAGS = -module -avoid-version -shared $(AM_LDFLAGS)
