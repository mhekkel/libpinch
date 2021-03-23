dnl        Copyright Maarten L. Hekkelman 2013-2021
dnl Distributed under the Boost Software License, Version 1.0.
dnl    (See accompanying file LICENSE_1_0.txt or copy at
dnl          http://www.boost.org/LICENSE_1_0.txt)

AC_PREREQ([2.69])

m4_define([libpinch_version_major],[1])
m4_define([libpinch_version_minor],[0])
m4_define([libpinch_version_micro],[0])
m4_define([libpinch_version_extra],[])
m4_define([libpinch_version],[libpinch_version_major().libpinch_version_minor().libpinch_version_micro()libpinch_version_extra])

AC_INIT([libpinch], [libpinch_version], [maarten@hekkelman.com])

AC_CONFIG_SRCDIR([src/channel.cpp])
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_MACRO_DIR([config/m4])

AC_PROG_INSTALL
PKG_PROG_PKG_CONFIG

dnl Switch to a C++ compiler, and check if it works.
AC_LANG(C++)
AX_CXX_COMPILE_STDCXX_17([noext])

AX_CHECK_COMPILE_FLAG([-fstandalone-debug],
	[
		CXXFLAGS="$CXXFLAGS -fstandalone-debug"
	] , , [-Werror])

dnl AX_CHECK_COMPILE_FLAG([-std=c++20],
dnl 	[
dnl 		CXX="$CXX -std=c++20"
dnl 	],
dnl 	[AC_MSG_ERROR("Compiler does not support c++20")],
dnl 	[])
dnl 
dnl AX_CHECK_COMPILE_FLAG([-fstandalone-debug],
dnl 	[
dnl 		CXXFLAGS="$CXXFLAGS -fstandalone-debug"
dnl 	] , , [-Werror])
dnl 
dnl AX_CHECK_COMPILE_FLAG([-fcoroutines],
dnl 	[
dnl 		CXXFLAGS="$CXXFLAGS -fcoroutines"
dnl 	] , , [-Werror])

dnl disable shared libraries, they break the build on MacOS... sigh
LT_INIT([disable-shared pic-only])
AC_SUBST(LIBTOOL_DEPS)

LIBPINCH_CURRENT=1
LIBPINCH_REVISION=1
LIBPINCH_AGE=1

LIBPINCH_LT_CURRENT="${LIBPINCH_CURRENT}"
LIBPINCH_LT_VERSION="${LIBPINCH_CURRENT}:${LIBPINCH_REVISION}:${LIBPINCH_AGE}"

AC_SUBST(LIBPINCH_LT_CURRENT)
AC_SUBST(LIBPINCH_LT_VERSION)

dnl and now for the semantic version
LIBPINCH_SEMANTIC_VERSION=libpinch_version
AC_SUBST(LIBPINCH_SEMANTIC_VERSION)

AC_SEARCH_LIBS([dlopen], [dl dld], [], [
  AC_MSG_ERROR([unable to find the dlopen() function])
])

AX_PTHREAD

AC_ARG_VAR([DEBUG], [Build a debug version of the application])

AX_BOOST_BASE([1.75])
AX_BOOST_ASIO
AX_BOOST_DATE_TIME
AX_BOOST_REGEX
AX_BOOST_IOSTREAMS
AX_BOOST_THREAD
AX_BOOST_COROUTINE
# AX_BOOST_CONTEXT2

AC_SEARCH_LIBS([exit], [boost_context], [
		BOOST_CONTEXT_LIB="-lboost_context"
		AC_SUBST(BOOST_CONTEXT_LIB)
	], [
  AC_MSG_ERROR([unable to find the boost_context library])
])


dnl Check for libcryptopp
AC_ARG_WITH([cryptopp],
	AS_HELP_STRING([--with-cryptopp=@<:@location@:>@], [Use the libcryptopp library as specified.]),
	[
		AS_IF([test -d ${withval}], [], [
			AC_MSG_ERROR(['${withval}'' is not a valid directory for --with-cryptopp])
		])

		CRYPTOPP_CFLAGS="-I ${withval}"
		CRYPTOPP_LIBS="-L${withval} -lcryptopp"

		AC_SUBST([CRYPTOPP_CFLAGS], [$CRYPTOPP_CFLAGS])
		AC_SUBST([CRYPTOPP_LIBS], [$CRYPTOPP_LIBS])
	])

AS_IF([test "x$CRYPTOPP_LIBS" = "x" ], [
	AC_CHECK_HEADER(
		[cryptopp/cryptlib.h], [],
		[AC_MSG_ERROR([Can't find the libcrypto++ header files. Make sure that libcrypto++ is installed.])])

	AX_CHECK_LIBRARY([CRYPTOPP], [cryptopp/cryptlib.h], [cryptopp],
		[
			CRYPTOPP_LIBS="-lcryptopp $LIBS"
		],
		[AC_MSG_ERROR([libcrtypo++ not found])])
])

dnl AS_IF([ test "x$CRYPTOPP_LIBS" = "x" && test -x "$PKG_CONFIG" ],
dnl 	AX_PKG_CHECK_MODULES([CRYPTOPP], [libcrypto++])
dnl )

dnl These are still needed outside the Debian environment
AX_CHECK_LIBRARY([LIBZ], [zlib.h], [z],
	[ LIBS="$LIBS -lz" ],
	[AC_MSG_ERROR([libz not found - compressed files not supported])])
AX_CHECK_LIBRARY([LIBBZ2], [bzlib.h], [bz2],
	[ LIBS="$LIBS -lbz2"],
	[AC_MSG_ERROR([libbz2 not found - compressed files not supported])])

AC_SUBST([LIBS], [$LIBS])

dnl for the documentation
AC_ARG_ENABLE(
	documentation,
	[AS_HELP_STRING([--enable-documentation], [Generate documentation])])
AC_ARG_VAR([DOXYGEN],
	[Path to doxygen needed to build reference documentation])
AC_PATH_TOOL([DOXYGEN], [doxygen], [nodoxygen])
AC_PATH_TOOL([QUICKBOOK], [quickbook], [noquickbook])
AC_PATH_TOOL([XSLTPROC], [xsltproc], [noxsltproc])
AC_PATH_TOOL([FOP], [fop], [nofop])
AC_PATH_TOOL([BJAM], [bjam], [nobjam])

AS_IF([test "$enable_documentation" = "yes"],
	[
		AS_IF([test "$DOXYGEN" = "nodoxygen" -o "$QUICKBOOX" = "noquickbook" -o "$XSLTPROC" = "noxsltproc" -o "$FOP" = "nofop" -o "$BJAM" = "nobjam"],
			[AC_MSG_ERROR([could not find the tools necessary to build the documentation])])

		BUILD_DOCS_TRUE=1
		AC_SUBST(BUILD_DOCS_TRUE)
])

dnl Process Makefile.in to create Makefile
AC_OUTPUT([GNUmakefile])
