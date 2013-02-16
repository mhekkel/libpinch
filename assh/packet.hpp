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

class opacket
{
  public:
					opacket();
					opacket(message_type message);
					opacket(const opacket& rhs);
					opacket(opacket&& rhs);
	opacket&		operator=(const opacket& rhs);
	opacket&		operator=(opacket&& rhs);

	void			write(std::ostream& os, int blocksize) const;
	
					operator std::vector<uint8>() const	{ return m_data; }

	template<typename INT>
	opacket&		operator<<(INT v);
	opacket&		operator<<(const char* v);
	opacket&		operator<<(const std::string& v);
	opacket&		operator<<(const std::vector<std::string>& v);
	opacket&		operator<<(const char* v[]);
	opacket&		operator<<(const std::vector<byte>& v);
	opacket&		operator<<(const CryptoPP::Integer& v);
	opacket&		operator<<(const opacket& v);
	
	std::vector<uint8>
					hash() const;

  protected:
	std::vector<uint8>	m_data;
};

class ipacket
{
  public:
					ipacket();
					ipacket(const ipacket& rhs);
					ipacket(ipacket&& rhs);
	ipacket&		operator=(const ipacket& rhs);
	ipacket&		operator=(ipacket&& rhs);

	bool			full();
	void			clear();
	void			append(const std::vector<char>& block);

	message_type	message() const						{ return m_message; }
					operator message_type() const		{ return m_message; }

					operator std::vector<uint8>() const	{ return m_data; }

	void			skip(uint32 bytes)					{ m_offset += bytes; }

	template<typename INT>
	ipacket&		operator>>(INT& v);
	ipacket&		operator>>(std::string& v);
	ipacket&		operator>>(std::vector<std::string>& v);
	ipacket&		operator>>(std::vector<byte>& v);
	ipacket&		operator>>(CryptoPP::Integer& v);
	ipacket&		operator>>(ipacket& v);

  protected:
	message_type	m_message;
	std::vector<uint8>
					m_data;
	uint32			m_offset, m_length;
};

template<typename INT>
opacket& opacket::operator<<(INT v)
{
	BOOST_STATIC_ASSERT(boost::is_integral<INT>::value);
	
	for (int i = sizeof(INT) - 1; i >= 0; --i)
		m_data.push_back(static_cast<uint8>(v >> (i * 8)));

	return *this;
}

template<typename INT>
ipacket& ipacket::operator>>(INT& v)
{
	BOOST_STATIC_ASSERT(boost::is_integral<INT>::value);
	
	if (m_offset + sizeof(INT) > m_data.size())
		throw packet_exception();
	
	for (int i = sizeof(INT) - 1; i >= 0; --i)
		v = v << 8 | m_data[m_offset++];

	return *this;
}

}
