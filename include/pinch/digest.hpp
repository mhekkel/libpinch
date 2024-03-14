//           Copyright Maarten L. Hekkelman 2021
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

/// \brief Simple implementation of very common digesting routines

#include "pinch/types.hpp"

#include <stdexcept>
#include <string>

namespace pinch
{

/// \brief Return 20 random bytes
blob random_hash();

/// \brief exception thrown when base64 input is invalid
class invalid_base64 : public std::invalid_argument
{
  public:
	invalid_base64()
		: invalid_argument("invalid base64")
	{
	}
};

/// \brief decode base64
blob decode_base64(std::string_view s);

/// \brief encode base64
std::string encode_base64(const blob &b);

/// \brief hmac/sha1 hashing
blob hmac_sha1(std::string_view message, const blob &key);

} // namespace pinch