cmake_minimum_required(VERSION 3.16)

project(libpinch VERSION 1.0.0 LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

include(GNUInstallDirs)
include(CheckFunctionExists)
include(CheckIncludeFiles)
include(FindFilesystem)
include(CheckLibraryExists)
include(CMakePackageConfigHelpers)
include(Dart)
include(GenerateExportHeader)

set(PACKAGE ${PROJECT_NAME})
set(PACKAGE_VERSION ${PROJECT_VERSION})
add_definitions(-DVERSION=${PACKAGE_VERSION})

set(CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(CMAKE_CXX_COMPILER_ID MATCHES Clang)
    if(WIN32)
		set(pinch_compile_flags "/clang:-fcoroutines-ts")
	else()
		set(pinch_compile_flags "-fcoroutines-ts")
	endif()
elseif(MSVC)
    check_include_file_cxx("coroutine" has_coroutine "/std:c++latest")
    if(NOT has_coroutine)
        message(STATUS "Try <experimental/coroutine> (Coroutines TS) instead of <coroutine> ...")
        check_include_file_cxx("experimental/coroutine" has_coroutine_ts "/std:c++17")
    endif()

	# has coroutine headers?
	if(has_coroutine)
		set(pinch_compile_flags "/std:c++latest")
	elseif(has_coroutine_ts)
		set(pinch_compile_flags "/std:c++17")
	else()
        message(FATAL_ERROR "There are no headers for C++ Coroutines")
    endif()
elseif(CMAKE_CXX_COMPILER_ID MATCHES GNU)
    #
    # expect GCC 10 or later
    #
    check_include_file_cxx("coroutine" has_coroutine "-fcoroutines")
	if(has_coroutine)
		set(pinch_compile_flags "-fcoroutines")
	endif()
endif()

# support compiler options for coroutine?
check_cxx_compiler_flag("${pinch_compile_flags}" support_coroutines)
if(NOT support_coroutines)
    message(FATAL_ERROR "The compiler doesn't support C++ Coroutines")
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${pinch_compile_flags}")
if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers")
elseif(MSVC)
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4")
endif()

find_package(Filesystem REQUIRED)
find_package(ZLIB REQUIRED)

# Build shared libraries by default (not my cup of tea, but hey)
option(BUILD_SHARED_LIBS "Build a shared library instead of a static one" OFF)
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)

if(MSVC)
    # make msvc standards compliant...
    add_compile_options(/permissive-)

	macro(get_WIN32_WINNT version)
		if (WIN32 AND CMAKE_SYSTEM_VERSION)
			set(ver ${CMAKE_SYSTEM_VERSION})
			string(REPLACE "." "" ver ${ver})
			string(REGEX REPLACE "([0-9])" "0\\1" ver ${ver})

			set(${version} "0x${ver}")
		endif()
	endmacro()

	get_WIN32_WINNT(ver)
	add_definitions(-D_WIN32_WINNT=${ver})

	# On Windows, do not install in the system location by default
	if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
		message("The library and auxiliary files will be installed in $ENV{LOCALAPPDATA}/pinch")
		set(CMAKE_INSTALL_PREFIX "$ENV{LOCALAPPDATA}/pinch" CACHE PATH "..." FORCE)
	endif()
endif()

set(CMAKE_THREAD_PREFER_PTHREAD)
set(THREADS_PREFER_PTHREAD_FLAG)
find_package(Threads REQUIRED)

find_path(CRYPTOPP_INCLUDE_DIR NAMES cryptopp/cryptlib.h crypto++/cryptlib.h REQUIRED)
find_library(CRYPTOPP_LIBRARY NAMES cryptopp crypto++ REQUIRED)

set(Boost_DETAILED_FAILURE_MSG ON)
if(NOT BUILD_SHARED_LIBS)
	set(Boost_USE_STATIC_LIBS ON)
endif()
find_package(Boost 1.75.0 REQUIRED COMPONENTS program_options system date_time regex coroutine)

list(APPEND PINCH_HEADERS
	${CMAKE_SOURCE_DIR}/include/pinch/detail/ssh_agent_impl.hpp
	${CMAKE_SOURCE_DIR}/include/pinch/error.hpp
	${CMAKE_SOURCE_DIR}/include/pinch/terminal_channel.hpp
	${CMAKE_SOURCE_DIR}/include/pinch/ssh_agent.hpp
	${CMAKE_SOURCE_DIR}/include/pinch/ssh_agent_channel.hpp
	${CMAKE_SOURCE_DIR}/include/pinch/x11_channel.hpp
	${CMAKE_SOURCE_DIR}/include/pinch/packet.hpp
	${CMAKE_SOURCE_DIR}/include/pinch/pinch.hpp
	${CMAKE_SOURCE_DIR}/include/pinch/crypto-engine.hpp
	${CMAKE_SOURCE_DIR}/include/pinch/digest.hpp
	${CMAKE_SOURCE_DIR}/include/pinch/known_hosts.hpp
	${CMAKE_SOURCE_DIR}/include/pinch/port_forwarding.hpp
	${CMAKE_SOURCE_DIR}/include/pinch/sftp_channel.hpp
	${CMAKE_SOURCE_DIR}/include/pinch/debug.hpp
	${CMAKE_SOURCE_DIR}/include/pinch/operations.hpp
	${CMAKE_SOURCE_DIR}/include/pinch/connection.hpp
	${CMAKE_SOURCE_DIR}/include/pinch/connection_pool.hpp
	${CMAKE_SOURCE_DIR}/include/pinch/channel.hpp
	${CMAKE_SOURCE_DIR}/include/pinch/key_exchange.hpp
	${CMAKE_SOURCE_DIR}/include/pinch/types.hpp
)

list(APPEND PINCH_SRC
	${CMAKE_SOURCE_DIR}/src/known_hosts.cpp
	${CMAKE_SOURCE_DIR}/src/port_forwarding.cpp
	${CMAKE_SOURCE_DIR}/src/connection.cpp
	${CMAKE_SOURCE_DIR}/src/debug.cpp
	${CMAKE_SOURCE_DIR}/src/error.cpp
	${CMAKE_SOURCE_DIR}/src/sftp_channel.cpp
	${CMAKE_SOURCE_DIR}/src/ssh_agent.cpp
	${CMAKE_SOURCE_DIR}/src/terminal_channel.cpp
	${CMAKE_SOURCE_DIR}/src/crypto-engine.cpp
	${CMAKE_SOURCE_DIR}/src/digest.cpp
	${CMAKE_SOURCE_DIR}/src/connection_pool.cpp
	${CMAKE_SOURCE_DIR}/src/x11_channel.cpp
	${CMAKE_SOURCE_DIR}/src/packet.cpp
	${CMAKE_SOURCE_DIR}/src/channel.cpp
	${CMAKE_SOURCE_DIR}/src/key_exchange.cpp
)

if(MSVC)
	list(APPEND PINCH_SRC
		${CMAKE_SOURCE_DIR}/src/win_ssh_agent_impl.cpp
	)
endif()

if(UNIX)
	list(APPEND PINCH_SRC
		${CMAKE_SOURCE_DIR}/src/posix_ssh_agent_impl.cpp
	)
endif()

add_library(pinch ${PINCH_SRC} ${PINCH_HEADERS})
set_target_properties(pinch PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_include_directories(pinch
	PUBLIC
	"$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>"
	"$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
	${Boost_INCLUDE_DIR} ${CRYPTOPP_INCLUDE_DIR}
)

target_include_directories(pinch PRIVATE ${CMAKE_SOURCE_DIR}/include PUBLIC ${Boost_INCLUDE_DIR} ${CRYPTOPP_INCLUDE_DIR} ${ZLIB_INCLUDE_DIR})
target_link_libraries(pinch PUBLIC ${Boost_LIBRARIES} ${CRYPTOPP_LIBRARY} ${CMAKE_THREAD_LIBS_INIT} std::filesystem ${ZLIB_LIBRARY})

if (CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang")
    target_link_options(pinch PRIVATE -undefined dynamic_lookup)
endif (CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang")

set(INCLUDE_INSTALL_DIR ${CMAKE_INSTALL_INCLUDEDIR} )
set(LIBRARY_INSTALL_DIR ${CMAKE_INSTALL_LIBDIR} )

generate_export_header(pinch EXPORT_FILE_NAME pinch/PINCH_export.hpp)

# Install rules

install(TARGETS pinch
	EXPORT pinchTargets
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
	INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(EXPORT pinchTargets
	FILE "pinchTargets.cmake"
	NAMESPACE pinch::
	DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/pinch
)

install(
	DIRECTORY include/pinch
	DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
	COMPONENT Devel
)

install(
	FILES "${CMAKE_CURRENT_BINARY_DIR}/pinch/PINCH_export.hpp"
	DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/pinch
	COMPONENT Devel
)

configure_package_config_file(Config.cmake.in
	${CMAKE_CURRENT_BINARY_DIR}/pinch/pinchConfig.cmake
	INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/pinch
	PATH_VARS INCLUDE_INSTALL_DIR LIBRARY_INSTALL_DIR
)

install(FILES
		"${CMAKE_CURRENT_BINARY_DIR}/pinch/pinchConfig.cmake"
		"${CMAKE_CURRENT_BINARY_DIR}/pinch/pinchConfigVersion.cmake"
	DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/pinch
	COMPONENT Devel
)

set(PINCH_MAJOR_VERSION 5)
set_target_properties(pinch PROPERTIES
	VERSION ${PROJECT_VERSION}
	SOVERSION 5.1
	INTERFACE_PINCH_MAJOR_VERSION 5)

set_property(TARGET pinch APPEND PROPERTY
  COMPATIBLE_INTERFACE_STRING PINCH_MAJOR_VERSION
)

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/pinch/pinchConfigVersion.cmake"
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY AnyNewerVersion
)

# pkgconfig support

set(prefix      ${CMAKE_INSTALL_PREFIX})
set(exec_prefix ${CMAKE_INSTALL_PREFIX})
set(libdir      ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR})
set(includedir  ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR})

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/libpinch.pc.in
	${CMAKE_CURRENT_BINARY_DIR}/libpinch.pc.in @ONLY)
file(GENERATE OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/libpinch.pc
	INPUT ${CMAKE_CURRENT_BINARY_DIR}/libpinch.pc.in)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libpinch.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

# Documentation
option(PINCH_BUILD_DOC "Build documentation" OFF)

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

		configure_file(${CMAKE_SOURCE_DIR}/doc/tools/quickbook.sh.in
			${CMAKE_CURRENT_BINARY_DIR}/tmp/quickbook.sh
			@ONLY)
		file(COPY ${CMAKE_CURRENT_BINARY_DIR}/tmp/quickbook.sh
			DESTINATION ${CMAKE_CURRENT_BINARY_DIR}
			FILE_PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ)
		file(REMOVE_RECURSE ${CMAKE_CURRENT_BINARY_DIR}/tmp/)
	else()
		set(QUICKBOOK_SCRIPT ${QUICKBOOK})
	endif()

	configure_file(${CMAKE_SOURCE_DIR}/doc/Jamfile.v2.in ${CMAKE_SOURCE_DIR}/doc/Jamfile.v2 @ONLY)
	
	add_custom_command(OUTPUT ${CMAKE_SOURCE_DIR}/doc/html/index.html
			${CMAKE_SOURCE_DIR}/doc/html ${CMAKE_SOURCE_DIR}/doc/bin
			${CMAKE_SOURCE_DIR}/doc/autodoc.xml
		COMMAND ${BJAM} ${CMAKE_SOURCE_DIR}/doc
		DEPENDS ${CMAKE_SOURCE_DIR}/doc/Jamfile.v2)
	add_custom_target(doc ALL DEPENDS ${CMAKE_SOURCE_DIR}/doc/html/index.html)
	install(DIRECTORY ${CMAKE_SOURCE_DIR}/doc/html DESTINATION ${CMAKE_INSTALL_DOCDIR}/${PACKAGE_NAME})
endif()

# Test applications

option(PINCH_BUILD_TESTS "Build test executables" OFF)

if(PINCH_BUILD_TESTS)

	enable_testing()

	#  unit parser serializer xpath json crypto http processor webapp soap rest security uri

	list(APPEND PINCH_tests coro service sftp unit)

	foreach(TEST IN LISTS PINCH_tests)
		set(PINCH_TEST "${TEST}-test")
		set(PINCH_TEST_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/test/${PINCH_TEST}.cpp")

		add_executable(${PINCH_TEST} ${PINCH_TEST_SOURCE})

		if("${TEST}" STREQUAL "http/processor")
			target_compile_definitions(${PINCH_TEST} PUBLIC DOCROOT=".")
		endif()

		target_include_directories(${PINCH_TEST} PRIVATE
			${CMAKE_CURRENT_SOURCE_DIR}/include
			${CMAKE_CURRENT_BINARY_DIR}  # for config.h
			${CMAKE_SOURCE_DIR}/include
		)

		target_link_libraries(${PINCH_TEST} PRIVATE pinch)

		if(MSVC)
			# Specify unwind semantics so that MSVC knowns how to handle exceptions
			target_compile_options(${PINCH_TEST} PRIVATE /EHsc)
		endif()

		if(${TEST} STREQUAL "sftp")
			set(${PINCH_TEST_ARGS} "localhost 22 maarten")
		else()
			set(${PINCH_TEST_ARGS} "")
		endif()

		add_test(NAME ${PINCH_TEST}
			COMMAND $<TARGET_FILE:${PINCH_TEST}> ${PINCH_TEST_ARGS}
			WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/test)

	endforeach()
endif()
