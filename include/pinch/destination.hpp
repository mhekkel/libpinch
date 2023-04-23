//           Copyright Maarten L. Hekkelman 2022
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include <optional>
#include <string>

// /// \file destination.hpp

// /// @brief  destination is a recursive type.
// struct destination
// {
// 	std::string username;
// 	std::string address;
// 	uint16_t port;
// 	std::optional<destination> proxy;

// 	destination() = default;
// 	destination(const std::string &username, const std::string address, uint16_t port = 22)
// 		: username(username)
// 		, address(address)
// 		, port(port)
// 	{
// 	}

// 	destination(const destination &) = default;
// 	destination &operator=(const destination &) = default;

// 	destination(destination &&) = default;
// 	destination &operator=(destination &&) = default;


// 	std::string string() const
// 	{
// 		std::string result = username + '@' + address;
// 		if (port != 22)
// 			result += ':' + std::to_string(port);

// 		if (proxy.has_value())
// 			result += " (via " + proxy->string() + ')';

// 		return result;
// 	}
// };
