//        Copyright Maarten L. Hekkelman 2013-2021
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

/// \brief dump packets to a stream

#include "pinch/packet.hpp"

#include <ostream>

namespace pinch
{

class ipacket;
class opacket;

std::ostream &operator<<(std::ostream &os, ipacket &p);
std::ostream &operator<<(std::ostream &os, opacket &p);

} // namespace pinch
