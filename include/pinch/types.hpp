//        Copyright Maarten L. Hekkelman 2013-2021
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

/// \file types.hpp
/// Common types in this library

#include <cstdint>
#include <vector>

namespace pinch
{

/// \brief The direction for an algorithm
enum class direction
{
	c2s, ///< Client to server
	s2c, ///< Server to client
	both ///< Both directions
};

/// \brief The five algorithms
enum class algorithm
{
	encryption,
	verification,
	compression,
	keyexchange,
	serverhostkey
};

// blob should be made a bit more secure one day

/// \brief Class containing a number of unsigned bytes
using blob = std::vector<uint8_t>;

} // namespace pinch
