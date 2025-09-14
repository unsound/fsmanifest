# Autoconf
AC_PREREQ(2.59)
AC_INIT([fsmanifest],[1.0],[catacombae@gmail.com])
AC_CONFIG_SRCDIR([src/fsmanifest.c])

# Environment
AC_CANONICAL_HOST
AC_CANONICAL_TARGET

# Automake
AM_INIT_AUTOMAKE(no-dist-gzip dist-bzip2)
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_MAINTAINER_MODE

# Options

# pthread_rwlock_t requires _GNU_SOURCE
AC_GNU_SOURCE

# Programs
AC_PROG_CC(gcc cc)
AM_PROG_CC_C_O

ifdef(
	[LT_INIT],
	[LT_INIT],
	[AC_PROG_LIBTOOL]
)

AC_PROG_INSTALL

# Environment

# Libraries

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([ \
	fcntl.h \
	unistd.h \
])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_STRUCT_ST_BLOCKS
AC_CHECK_MEMBERS([struct stat.st_rdev])
AC_CHECK_MEMBERS([struct stat.st_atim])
AC_CHECK_MEMBERS([struct stat.st_atimespec])
AC_CHECK_MEMBERS([struct stat.st_atimensec])

# Checks for library functions.
AC_FUNC_STAT
AC_CHECK_FUNCS([ \
	openat \
	fdopendir \
	statx \
])
AC_SYS_LARGEFILE

# Determine which library to use for SHA512 hashing.
case "${target_os}" in
darwin*)
	# On macOS we use the built-in CommonCrypto. No flags needed.
	;;
freebsd*)
	# On FreeBSD we check that libcrypto is available using AC_CHECK_LIB as
	# there is no .pc file.
	AC_CHECK_LIB(
		[crypto],
		[EVP_sha512],
		[],
		[AC_MSG_ERROR([[Cannot find the required OpenSSL libraries (need OpenSSL with SHA-512 support).]])]
	)
	;;
*)
	# On other systems we use the OpenSSL library, which is located using
	# pkg-config.

	if test -z "$PKG_CONFIG"; then
		AC_PATH_PROG(PKG_CONFIG, pkg-config, no)
	fi

	if test "x${PKG_CONFIG}" = "xno"; then
		AC_MSG_ERROR([Unable to locate pkg-config, needed for determining OpenSSL library parameters.])
	fi

	PKG_CHECK_MODULES(
		[OPENSSL_MODULE],
		[openssl],
		[
			CFLAGS="${CFLAGS} ${OPENSSL_MODULE_CFLAGS}"
			LIBS="${LIBS} ${OPENSSL_MODULE_LIBS}"
		],
		[AC_MSG_ERROR([[Cannot find the required OpenSSL libraries (need OpenSSL with SHA-512 support). Please install libssl-dev (Ubuntu/Debian), openssl-devel (Fedora) or equivalent.]])]
	)

	;;
esac

if test "$GCC" = "yes" ; then
	# We add -Wall to enable some compiler warnings.
	CFLAGS="${CFLAGS} -Wall"
fi

# Settings
AM_CONDITIONAL([WITH_OPENSSL], [test "x${have_openssl}" = "xyes"])

# generate files
AC_CONFIG_FILES([
	Makefile
	src/Makefile
])
AC_OUTPUT

echo "You can type now 'make' to build fsmanifest."
