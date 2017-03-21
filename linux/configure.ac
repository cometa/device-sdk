# Process this file with autoconf to produce a configure script.

AC_INIT([libcometa],[1.0],[bug-device-sdk@visiblenergy.com])
AM_INIT_AUTOMAKE

AC_CONFIG_SRCDIR([src/libcometa.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL
AC_PROG_INSTALL

AC_CANONICAL_HOST
AC_CONFIG_MACRO_DIR([m4])

dnl CFLAGS="-DWITH_SSL -DDEBUG"
CFLAGS="-DWITH_SSL"

# Checks for libraries.
AC_CHECK_LIB([crypto],[X509_free])
AC_CHECK_LIB([pthread],[pthread_rwlock_wrlock])
AC_CHECK_LIB([ssl],[SSL_get_peer_certificate])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h limits.h netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h strings.h sys/ioctl.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_CHECK_FUNCS([memchr memmove memset select socket strcasecmp strdup strtoul])

AC_OUTPUT(Makefile src/Makefile samples/Makefile)
