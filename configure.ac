AC_INIT([libassh], 1.1, [maarten@hekkelman.com])

dnl Switch to a C++ compiler, and check if it works.
AC_LANG(C++)
AX_CXX_COMPILE_STDCXX_17([noext])

AC_CONFIG_SRCDIR([src/channel.cpp])
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_MACRO_DIR([config/m4])

AX_BOOST_BASE([1.73])

AX_BOOST_ASIO

AC_PROG_INSTALL

AC_ARG_VAR([DEBUG], [Build a debug version of the library])

# AC_ARG_ENABLE(
# 	debug,
# 	[AS_HELP_STRING([--enable-debug], [Generate a debug version of the library])],
# 	[],
# 	[enable_debug=auto])

dnl Process Makefile.in to create Makefile
AC_OUTPUT([GNUmakefile])
