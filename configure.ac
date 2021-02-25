AC_PREREQ([2.69])

m4_define([libassh_version_major],[1])
m4_define([libassh_version_minor],[0])
m4_define([libassh_version_micro],[0])
m4_define([libassh_version_extra],[])
m4_define([libassh_version],[libassh_version_major().libassh_version_minor().libassh_version_micro()libassh_version_extra])

AC_INIT([libassh], [libassh_version], [maarten@hekkelman.com])

dnl Switch to a C++ compiler, and check if it works.
AC_LANG(C++)
AX_CXX_COMPILE_STDCXX_17([noext])

AX_CHECK_COMPILE_FLAG([-fstandalone-debug],
	[
		CXXFLAGS="$CXXFLAGS -fstandalone-debug"
	] , , [-Werror])

AC_CONFIG_SRCDIR([src/channel.cpp])
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_MACRO_DIR([config/m4])

AC_PROG_INSTALL
PKG_PROG_PKG_CONFIG

dnl disable shared libraries, they break the build on MacOS... sigh
LT_INIT([disable-shared pic-only])
AC_SUBST(LIBTOOL_DEPS)

LIBASSH_CURRENT=1
LIBASSH_REVISION=1
LIBASSH_AGE=1

LIBASSH_LT_CURRENT="${LIBASSH_CURRENT}"
LIBASSH_LT_VERSION="${LIBASSH_CURRENT}:${LIBASSH_REVISION}:${LIBASSH_AGE}"

AC_SUBST(LIBASSH_LT_CURRENT)
AC_SUBST(LIBASSH_LT_VERSION)

dnl and now for the semantic version
LIBASSH_SEMANTIC_VERSION=libassh_version
AC_SUBST(LIBASSH_SEMANTIC_VERSION)

AX_PTHREAD

AC_ARG_VAR([DEBUG], [Build a debug version of the application])

AX_BOOST_BASE([1.71])
AX_BOOST_ASIO
AX_BOOST_DATE_TIME
AX_BOOST_REGEX
AX_BOOST_IOSTREAMS

if test -x "$PKG_CONFIG"
then
	AX_PKG_CHECK_MODULES([CRYPTOPP], [libcrypto++], [], [], [AC_MSG_ERROR([the required package libcrypto++ is not installed])])
else
	AC_CHECK_HEADER(
		[cryptopp/cryptlib.h],
		[
			CRYPTOPP_CFLAGS="-I ${withval}/include"
		],
		[AC_MSG_ERROR([
Can't find the libcrypto++ header files. Make sure that libcrypto++ is installed.])])

	AX_CHECK_LIBRARY([CRYPTOPP], [cryptopp/cryptlib.h], [crypto++],
		[
			LIBS="-L${withval}/lib -lcrypto++ $LIBS"
		],
		[AC_MSG_ERROR([libcrtypo++ not found])])
fi

dnl These are still needed outside the Debian environment
AX_CHECK_LIBRARY([LIBZ], [zlib.h], [z],
	[ LIBS="$LIBS -lz" ],
	[AC_MSG_ERROR([libz not found - compressed files not supported])])
AX_CHECK_LIBRARY([LIBBZ2], [bzlib.h], [bz2],
	[ LIBS="$LIBS -lbz2"],
	[AC_MSG_ERROR([libbz2 not found - compressed files not supported])])

AC_SUBST([LIBS], [$LIBS])

dnl Process Makefile.in to create Makefile
AC_OUTPUT([GNUmakefile])
