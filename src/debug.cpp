//        Copyright Maarten L. Hekkelman 2013-2021
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)


#include "pinch/debug.hpp"
#include "pinch/packet.hpp"

namespace pinch
{

// hex dump the packet
void print(std::ostream &os, const blob &b)
{
	os << "dumping buffer of " << b.size() << " bytes" << std::endl;

	const char kHex[] = "0123456789abcdef";
	char s[] = "xxxxxxxx  cccc cccc cccc cccc  cccc cccc cccc cccc  |................|";
	const int kHexOffset[] = {10, 12, 15, 17, 20, 22, 25, 27, 31, 33, 36, 38, 41, 43, 46, 48};
	const int kAsciiOffset = 53;

	uint32_t offset = 0;

	while (offset < b.size())
	{
		size_t rr = b.size() - offset;
		if (rr > 16)
			rr = 16;

		char *t = s + 7;
		long o = offset;

		while (t >= s)
		{
			*t-- = kHex[o % 16];
			o /= 16;
		}

		for (size_t i = 0; i < rr; ++i)
		{
			uint8_t uint8_t = b[offset + i];

			s[kHexOffset[i] + 0] = kHex[uint8_t >> 4];
			s[kHexOffset[i] + 1] = kHex[uint8_t & 0x0f];
			if (uint8_t < 128 and not iscntrl(uint8_t) and isprint(uint8_t))
				s[kAsciiOffset + i] = uint8_t;
			else
				s[kAsciiOffset + i] = '.';
		}

		for (int i = rr; i < 16; ++i)
		{
			s[kHexOffset[i] + 0] = ' ';
			s[kHexOffset[i] + 1] = ' ';
			s[kAsciiOffset + i] = ' ';
		}

		os << s << std::endl;

		offset += rr;
	}
}

std::ostream &operator<<(std::ostream &os, pinch::opacket &b)
{
	print(os, b);
	return os;
}

std::ostream &operator<<(std::ostream &os, pinch::ipacket &b)
{
	print(os, b);
	return os;
}

} // namespace pinch
