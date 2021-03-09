//        Copyright Maarten L. Hekkelman 2013-2021
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include <cstdint>
#include <vector>

namespace pinch
{

enum class direction { c2s, s2c, both };
enum class algorithm { encryption, verification, compression, keyexchange };

// blob should be made a bit more secure one day
using blob = std::vector<uint8_t>;


}
