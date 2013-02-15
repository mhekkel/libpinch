//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include <assh/config.hpp>

#include <vector>

#include <boost/static_assert.hpp>
#include <boost/asio.hpp>
#include <boost/type_traits/is_integral.hpp>

#include <cryptopp/integer.h>

namespace assh
{
	
class packet_exception : public std::exception
{
};
	
enum message_type : uint8
{
	undefined,

	disconnect = 1, ignore, unimplemented, debug, service_request, service_accept,

	kexinit = 20, newkeys,

	kexdh_init = 30, kexdh_reply,

 	userauth_request = 50, userauth_failure, userauth_success, userauth_banner,

	userauth_info_request = 60, userauth_info_response,

	global_request = 80, request_success, request_failure,

	channel_open = 90, channel_open_confirmation, channel_open_failure,
	channel_window_adjust, channel_data, channel_extended_data,
	channel_eof, channel_close, channel_request, channel_success,
	channel_failure,
};

class packet
{
  public:
					packet(message_type message);
					template<typename MutableBufferSequence>
					packet(const MutableBufferSequence& buffers);
					packet(const packet& rhs);
					packet(packet&& rhs);
	packet&			operator=(const packet& rhs);
	packet&			operator=(packet&& rhs);
	virtual			~packet();

	message_type	message() const					{ return m_message; }
					operator message_type() const	{ return m_message; }

	void			to_buffers(uint32 blocksize, std::vector<boost::asio::const_buffer>& buffers);
	
	template<typename INT>
	packet&			operator<<(INT v);
	packet&			operator<<(const char* v);
	packet&			operator<<(const std::string& v);
	packet&			operator<<(const std::vector<byte>& v);
	packet&			operator<<(const CryptoPP::Integer& v);
	packet&			operator<<(const packet& v);

	template<typename INT>
	packet&			operator>>(INT& v);
	packet&			operator>>(std::string& v);
	packet&			operator>>(std::vector<byte>& v);
	packet&			operator>>(CryptoPP::Integer& v);
	packet&			operator>>(packet& v);

  protected:

	message_type	m_message;
	std::vector<uint8>
					m_data;
	uint32			m_offset;
};

template<typename INT>
packet& packet::operator<<(INT v)
{
	BOOST_STATIC_ASSERT(boost::is_integral<INT>::value);
	
	for (int i = sizeof(INT) - 1; i >= 0; --i)
		m_data.push_back(static_cast<uint8>(v >> (i * 8)));

	return *this;
}

template<typename INT>
packet& packet::operator>>(INT& v)
{
	BOOST_STATIC_ASSERT(boost::is_integral<INT>::value);
	
	if (m_offset + sizeof(INT) > m_data.size())
		throw packet_exception();
	
	for (int i = sizeof(INT) - 1; i >= 0; --i)
		v = v << 8 | m_data[m_offset++];

	return *this;
}

}
