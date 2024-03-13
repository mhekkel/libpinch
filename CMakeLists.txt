cmake_minimum_required(VERSION 3.16)

project(libpinch VERSION 1.1.1 LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

include(CTest)

option(USE_BOOST_ASIO "Use the asio library from Boost instead of the non-boost version" OFF)

# Documentation
option(PINCH_BUILD_DOC "Build documentation" OFF)

# include(GNUInstallDirs)
# include(CheckFunctionExists)
# include(CheckIncludeFiles)
# include(FindFilesystem)
# include(CheckLibraryExists)
# include(CMakePackageConfigHelpers)
# include(GenerateExportHeader)

# if(CMAKE_CXX_COMPILER_ID MATCHES Clang AND CMAKE_CXX_COMPILER_VERSION LESS 16.0.0)
# 	if(WIN32)
# 		set(pinch_compile_flags "/clang:-fcoroutines")
# 	else()
# 		set(pinch_compile_flags "-fcoroutines")
# 	endif()
# elseif(MSVC)
# 	check_include_file_cxx("coroutine" has_coroutine "/std:c++latest")

# 	if(NOT has_coroutine)
# 		message(STATUS "Try <experimental/coroutine> (Coroutines TS) instead of <coroutine> ...")
# 		check_include_file_cxx("experimental/coroutine" has_coroutine_ts "/std:c++20")
# 	endif()

# 	# has coroutine headers?
# 	if(has_coroutine)
# 		set(pinch_compile_flags "/std:c++latest")
# 	elseif(has_coroutine_ts)
# 		set(pinch_compile_flags "/std:c++20")
# 	else()
# 		message(FATAL_ERROR "There are no headers for C++ Coroutines")
# 	endif()
# elseif(CMAKE_CXX_COMPILER_ID MATCHES GNU)
# 	#
# 	# expect GCC 10 or later
# 	#
# 	check_include_file_cxx("coroutine" has_coroutine "-fcoroutines")

# 	if(has_coroutine)
# 		set(pinch_compile_flags "-fcoroutines")
# 	endif()
# endif()

# support compiler options for coroutine?
# check_cxx_compiler_flag("${pinch_compile_flags}" support_coroutines)

# if(NOT support_coroutines)
# 	message(FATAL_ERROR "The compiler doesn't support C++ Coroutines")
# endif()

# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${pinch_compile_flags}")

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers")
elseif(MSVC)
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4")
endif()

if(MSVC)
	# Avoid linking the shared library of zlib
	# Search ZLIB_ROOT first if it is set.
	if(ZLIB_ROOT)
		set(_ZLIB_SEARCH_ROOT PATHS ${ZLIB_ROOT} NO_DEFAULT_PATH)
		list(APPEND _ZLIB_SEARCHES _ZLIB_SEARCH_ROOT)
	endif()

	# Normal search.
	set(_ZLIB_x86 "(x86)")
	set(_ZLIB_SEARCH_NORMAL
		PATHS "[HKEY_LOCAL_MACHINE\\SOFTWARE\\GnuWin32\\Zlib;InstallPath]"
			"$ENV{ProgramFiles}/zlib"
			"$ENV{ProgramFiles${_ZLIB_x86}}/zlib")
	unset(_ZLIB_x86)
	list(APPEND _ZLIB_SEARCHES _ZLIB_SEARCH_NORMAL)

	foreach(search ${_ZLIB_SEARCHES})
    	find_library(ZLIB_LIBRARY NAMES zlibstatic NAMES_PER_DIR ${${search}} PATH_SUFFIXES lib)
	endforeach()
endif()
find_package(ZLIB REQUIRED)

if(USE_BOOST_ASIO)
	find_package(Boost 1.82 COMPONENTS headers REQUIRED)
	set(ASIO_INCLUDE_DIR ${Boost_INCLUDE_DIR})
	message(STATUS "Using asio from boost")

	configure_file(${PROJECT_SOURCE_DIR}/cmake/asio-boost.hpp.in ${PROJECT_SOURCE_DIR}/include/pinch/asio.hpp @ONLY)
else()
	if(MSVC)
		find_file(ASIO asio.hpp)
	else()
		pkg_check_modules(ASIO asio>=1.28 REQUIRED IMPORTED_TARGET)
	endif()

	message(STATUS "Using standalone asio")

	configure_file(${PROJECT_SOURCE_DIR}/cmake/asio.hpp.in ${PROJECT_SOURCE_DIR}/include/pinch/asio.hpp @ONLY)
endif()

if(WIN32)
	if(${CMAKE_SYSTEM_VERSION} GREATER_EQUAL 10) # Windows 10
		add_definitions(-D _WIN32_WINNT=0x0A00)
	elseif(${CMAKE_SYSTEM_VERSION} EQUAL 6.3) # Windows 8.1
		add_definitions(-D _WIN32_WINNT=0x0603)
	elseif(${CMAKE_SYSTEM_VERSION} EQUAL 6.2) # Windows 8
		add_definitions(-D _WIN32_WINNT=0x0602)
	elseif(${CMAKE_SYSTEM_VERSION} EQUAL 6.1) # Windows 7
		add_definitions(-D _WIN32_WINNT=0x0601)
	elseif(${CMAKE_SYSTEM_VERSION} EQUAL 6.0) # Windows Vista
		add_definitions(-D _WIN32_WINNT=0x0600)
	else() # Windows XP (5.1)
		add_definitions(-D _WIN32_WINNT=0x0501)
	endif()

	add_definitions(-DNOMINMAX)

	# We do not want to write an export file for all our symbols...
	set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif()


if(MSVC)
	# make msvc standards compliant...
	add_compile_options(/permissive-)

	# make msvc standards compliant...
	add_compile_options(/permissive- /bigobj)
	add_link_options(/NODEFAULTLIB:library)

	if(BUILD_SHARED_LIBS)
		set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
	else()
		set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
	endif()
endif()

set(CMAKE_THREAD_PREFER_PTHREAD)
set(THREADS_PREFER_PTHREAD_FLAG)
find_package(Threads REQUIRED)

find_path(CRYPTOPP_INCLUDE_DIR NAMES cryptopp/cryptlib.h crypto++/cryptlib.h REQUIRED)
find_library(CRYPTOPP_LIBRARY NAMES cryptopp crypto++ cryptlib REQUIRED)

# The pinch library

list(APPEND PINCH_HEADERS
	include/pinch.hpp
	include/pinch/detail/ssh_agent_impl.hpp
	include/pinch/error.hpp
	include/pinch/terminal_channel.hpp
	include/pinch/ssh_agent.hpp
	include/pinch/ssh_agent_channel.hpp
	include/pinch/x11_channel.hpp
	include/pinch/packet.hpp
	include/pinch/crypto-engine.hpp
	include/pinch/digest.hpp
	include/pinch/known_hosts.hpp
	include/pinch/port_forwarding.hpp
	include/pinch/sftp_channel.hpp
	include/pinch/debug.hpp
	include/pinch/operations.hpp
	include/pinch/connection.hpp
	include/pinch/connection_pool.hpp
	include/pinch/channel.hpp
	include/pinch/key_exchange.hpp
	include/pinch/types.hpp
)

list(APPEND PINCH_SRC
	src/known_hosts.cpp
	src/port_forwarding.cpp
	src/connection.cpp
	src/debug.cpp
	src/error.cpp
	src/sftp_channel.cpp
	src/ssh_agent.cpp
	src/terminal_channel.cpp
	src/crypto-engine.cpp
	src/digest.cpp
	src/connection_pool.cpp
	src/x11_channel.cpp
	src/packet.cpp
	src/channel.cpp
	src/key_exchange.cpp
)

if(MSVC)
	list(APPEND PINCH_SRC
		src/win_ssh_agent_impl.cpp
	)
endif()

if(UNIX)
	list(APPEND PINCH_SRC
		src/posix_ssh_agent_impl.cpp
	)
endif()

add_library(pinch)
add_library(pinch::pinch ALIAS pinch)

target_sources(pinch
	PRIVATE ${PINCH_SRC}
	PUBLIC
	FILE_SET public_headers TYPE HEADERS
	BASE_DIRS
	${CMAKE_CURRENT_SOURCE_DIR}
	FILES
	${PINCH_HEADERS}
	)

set_target_properties(pinch PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_include_directories(pinch
	PUBLIC
	"$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>"
	"$<INSTALL_INTERFACE:include>"
	${CRYPTOPP_INCLUDE_DIR} ${ASIO_INCLUDE_DIR}
)

target_link_libraries(pinch PUBLIC ${CRYPTOPP_LIBRARY} ${CMAKE_THREAD_LIBS_INIT} ZLIB::ZLIB)

# Install rules
install(TARGETS pinch
	EXPORT pinch
	FILE_SET public_headers DESTINATION include)

install(EXPORT pinch
	FILE pinch-targets.cmake
	NAMESPACE pinch::
	DESTINATION lib/cmake/pinch
)

configure_file(${PROJECT_SOURCE_DIR}/cmake/pinch-config.cmake.in
	${CMAKE_CURRENT_BINARY_DIR}/pinch-config.cmake @ONLY)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/pinch-config.cmake
	DESTINATION lib/cmake/pinch)

if(PINCH_BUILD_DOC)
	find_program(DOXYGEN doxygen)
	find_program(QUICKBOOK quickbook)
	find_program(XSLTPROC xsltproc)
	find_program(FOP fop)
	find_program(BJAM bjam)

	if(NOT DOXYGEN)
		list(APPEND MISSING_DOC_TOOL_LIST doxygen)
	endif()

	if(NOT QUICKBOOK)
		list(APPEND MISSING_DOC_TOOL_LIST quickbook)
	endif()

	if(NOT XSLTPROC)
		list(APPEND MISSING_DOC_TOOL_LIST xsltproc)
	endif()

	if(NOT FOP)
		list(APPEND MISSING_DOC_TOOL_LIST fop)
	endif()

	if(NOT BJAM)
		list(APPEND MISSING_DOC_TOOL_LIST bjam)
	endif()

	if(DEFINED MISSING_DOC_TOOL_LIST)
		list(JOIN MISSING_DOC_TOOL_LIST ", " MISSING_DOC_TOOLS)
		message(FATAL_ERROR "Cannot create documentation since the following applications could not be found: ${MISSING_DOC_TOOLS}")
	endif()

	make_directory(doc)

	if(UNIX)
		set(QUICKBOOK_SCRIPT "${CMAKE_CURRENT_BINARY_DIR}/quickbook.sh")

		configure_file(${PROJECT_SOURCE_DIR}/doc/tools/quickbook.sh.in
			${CMAKE_CURRENT_BINARY_DIR}/tmp/quickbook.sh
			@ONLY)
		file(COPY ${CMAKE_CURRENT_BINARY_DIR}/tmp/quickbook.sh
			DESTINATION ${CMAKE_CURRENT_BINARY_DIR}
			FILE_PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ)
		file(REMOVE_RECURSE ${CMAKE_CURRENT_BINARY_DIR}/tmp/)
	else()
		set(QUICKBOOK_SCRIPT ${QUICKBOOK})
	endif()

	configure_file(${PROJECT_SOURCE_DIR}/doc/Jamfile.v2.in ${PROJECT_SOURCE_DIR}/doc/Jamfile.v2 @ONLY)

	add_custom_command(OUTPUT ${PROJECT_SOURCE_DIR}/doc/html/index.html
		${PROJECT_SOURCE_DIR}/doc/html ${PROJECT_SOURCE_DIR}/doc/bin
		${PROJECT_SOURCE_DIR}/doc/autodoc.xml
		COMMAND ${BJAM} ${PROJECT_SOURCE_DIR}/doc
		DEPENDS ${PROJECT_SOURCE_DIR}/doc/Jamfile.v2)
	add_custom_target(doc ALL DEPENDS ${PROJECT_SOURCE_DIR}/doc/html/index.html)
	install(DIRECTORY ${PROJECT_SOURCE_DIR}/doc/html DESTINATION ${CMAKE_INSTALL_DOCDIR}/${PACKAGE_NAME})
endif()

# Test applications
option(PINCH_BUILD_TESTS "Build test executables" OFF)

if(PINCH_BUILD_TESTS)
	add_subdirectory(test)
endif()
