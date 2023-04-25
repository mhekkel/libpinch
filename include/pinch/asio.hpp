//          Copyright Maarten L. Hekkelman 2023
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

#if defined(USE_BOOST_ASIO) and USE_BOOST_ASIO

#include <boost/asio.hpp>

#if not __cpp_impl_coroutine
#error "libpinch now requires coroutines"
#endif

#include <boost/asio/execution.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <coroutine>

namespace asio_ns = ::boost::asio;
namespace system_ns = ::boost::system;

#else

#include <asio.hpp>

#if not __cpp_impl_coroutine
#error "libpinch now requires coroutines"
#endif

#include <asio/execution.hpp>
#include <asio/use_awaitable.hpp>

#include <coroutine>

namespace asio_ns = ::asio;
namespace system_ns = ::std;

#endif
