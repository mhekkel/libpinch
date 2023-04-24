//        Copyright Maarten L. Hekkelman 2013-2021
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

/// \file pinch.hpp
/// Generic header, not much here

#include "pinch/asio.hpp"
#include "pinch/channel.hpp"
#include "pinch/connection.hpp"
#include "pinch/connection_pool.hpp"
#include "pinch/crypto-engine.hpp"
#include "pinch/debug.hpp"
#include "pinch/digest.hpp"
#include "pinch/error.hpp"
#include "pinch/key_exchange.hpp"
#include "pinch/known_hosts.hpp"
#include "pinch/operations.hpp"
#include "pinch/packet.hpp"
#include "pinch/port_forwarding.hpp"
#include "pinch/sftp_channel.hpp"
#include "pinch/ssh_agent.hpp"
#include "pinch/ssh_agent_channel.hpp"
#include "pinch/terminal_channel.hpp"
#include "pinch/types.hpp"
#include "pinch/x11_channel.hpp"

#ifndef NDEBUG
#include "pinch/debug.hpp"
#endif
