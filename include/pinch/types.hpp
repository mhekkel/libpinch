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
