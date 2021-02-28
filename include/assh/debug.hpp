//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include <iostream>

namespace assh
{

class ipacket;
class opacket;

std::ostream& operator<<(std::ostream& os, ipacket& p);
std::ostream& operator<<(std::ostream& os, opacket& p);

} // namespace assh
