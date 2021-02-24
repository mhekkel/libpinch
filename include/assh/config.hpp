//            Copyright Maarten L. Hekkelman 2013
//  Distributed under the Boost Software License, Version 1.0.
//     (See accompanying file LICENSE_1_0.txt or copy at
//           http://www.boost.org/LICENSE_1_0.txt)

#pragma once

// some very common types

namespace assh
{
enum class direction { c2s, s2c, both };
enum class algorithm { encryption, verification, compression, keyexchange };
}

// set DEBUG flag

#if DEBUG or _DEBUG or DEBUG_
#undef DEBUG
#define DEBUG 1
#undef NDEBUG
#include <assh/debug.hpp>
#endif
