//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <assh/config.hpp>

#include <assh/debug.hpp>

using namespace std;

// hex dump the packet
ostream& operator<<(ostream& os, vector<boost::asio::const_buffer>& b)
{
	size_t size = boost::asio::buffer_size(b);
	os << "dumping buffer of " << size << " bytes" << endl;

	const char kHex[] = "0123456789abcdef";
	char s[] = "xxxxxxxx  cccc cccc cccc cccc  cccc cccc cccc cccc  |................|";
	const int kHexOffset[] = { 10, 12, 15, 17, 20, 22, 25, 27, 31, 33, 36, 38, 41, 43, 46, 48 };
	const int kAsciiOffset = 53;
	
	uint32 offset = 0;
	
	typedef vector<boost::asio::const_buffer> buffers_type;
	typedef boost::asio::buffers_iterator<buffers_type, uint8> buffer_iterator;
	buffer_iterator bi(buffer_iterator::begin(b));
	buffer_iterator ei(buffer_iterator::end(b));
	
	while (bi != ei)
	{
		size_t rr = ei - bi;
		if (rr > 16)
			rr = 16;
		buffer_iterator e2 = bi + rr;
		
		char* t = s + 7;
		long o = offset;
		
		while (t >= s)
		{
			*t-- = kHex[o % 16];
			o /= 16;
		}
		
		for (size_t i = 0; i < rr; ++i)
		{
			uint8 byte = *(bi + i);
			
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
		bi += rr;
	}

	return os;
}

