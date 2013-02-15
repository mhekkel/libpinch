//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include <vector>
#include <iostream>
#include <boost/asio.hpp>

std::ostream& operator<<(std::ostream& os, std::vector<boost::asio::const_buffer>& b);

