AUTOMAKE_OPTIONS       = subdir-objects
lib_LTLIBRARIES        = libcometa.la

libcometa_la_SOURCES   = libcometa.c \
                         libcometa.h \
                         http_parser.c \
                         http_parser.h

libcometa_la_CFLAGS = $(LIBCFLAGS)
libcometa_la_LDFLAGS = -version-info 1:0:0
include_HEADERS = libcometa.h
