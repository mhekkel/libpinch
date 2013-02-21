//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include <iostream>

#include <assh/packet.hpp>

std::ostream& operator<<(std::ostream& os, assh::ipacket& p);
std::ostream& operator<<(std::ostream& os, assh::opacket& p);

