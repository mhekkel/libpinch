cmake_minimum_required(VERSION 3.16)

project(libpinch VERSION 1.1.1 LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

include(FindPkgConfig)
include(CMakePackageConfigHelpers)
include(CTest)

option(USE_BOOST_ASIO "Use the asio library from Boost instead of the non-boost version" OFF)

# Documentation
option(PINCH_BUILD_DOC "Build documentation" OFF)
option(PINCH_BUILD_EXAMPLES "Build examples" ON)

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
		pkg_check_modules(ASIO asio>=1.27 REQUIRED IMPORTED_TARGET)
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
target_compile_features(pinch PUBLIC cxx_std_20)

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

configure_package_config_file(
	${PROJECT_SOURCE_DIR}/cmake/pinch-config.cmake.in
	${CMAKE_CURRENT_BINARY_DIR}/pinch-config.cmake
	INSTALL_DESTINATION lib/cmake/pinch)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/pinch-config.cmake
	DESTINATION lib/cmake/pinch)

if(PINCH_BUILD_DOC)
	add_subdirectory(doc)
endif()

# Test applications
option(PINCH_BUILD_TESTS "Build test executables" OFF)

if(PINCH_BUILD_TESTS)
	add_subdirectory(test)
endif()

if(PINCH_BUILD_EXAMPLES)
	add_subdirectory(examples)
endif()