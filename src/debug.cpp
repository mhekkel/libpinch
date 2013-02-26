//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <assh/config.hpp>

#include <assh/packet.hpp>
#include <assh/debug.hpp>

using namespace std;

// hex dump the packet
void print(ostream& os, const vector<uint8>& b)
{
	os << "dumping buffer of " << b.size() << " bytes" << endl;

	const char kHex[] = "0123456789abcdef";
	char s[] = "xxxxxxxx  cccc cccc cccc cccc  cccc cccc cccc cccc  |................|";
	const int kHexOffset[] = { 10, 12, 15, 17, 20, 22, 25, 27, 31, 33, 36, 38, 41, 43, 46, 48 };
	const int kAsciiOffset = 53;
	
	uint32 offset = 0;
		
	while (offset < b.size())
	{
		size_t rr = b.size() - offset;
		if (rr > 16)
			rr = 16;
		
		char* t = s + 7;
		long o = offset;
		
		while (t >= s)
		{
			*t-- = kHex[o % 16];
			o /= 16;
		}
		
		for (size_t i = 0; i < rr; ++i)
		{
			uint8 byte = b[offset + i];
			
			s[kHexOffset[i] + 0] = kHex[byte >> 4];
			s[kHexOffset[i] + 1] = kHex[byte & 0x0f];
			if (byte < 128 and not iscntrl(byte) and isprint(byte))
				s[kAsciiOffset + i] = byte;
			else
				s[kAsciiOffset + i] = '.';
		}
		
		for (int i = rr; i < 16; ++i)
		{
			s[kHexOffset[i] + 0] = ' ';
			s[kHexOffset[i] + 1] = ' ';
			s[kAsciiOffset + i] = ' ';
		}
		
		os << s << endl;
		
		offset += rr;
	}
}

ostream& operator<<(ostream& os, assh::opacket& b)
{
	print(os, b);
	return os;
}

ostream& operator<<(ostream& os, assh::ipacket& b)
{
	print(os, b);
	return os;
}

