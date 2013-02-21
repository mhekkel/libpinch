//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include <assh/config.hpp>

#include <vector>
#include <deque>

#include <boost/static_assert.hpp>
#include <boost/asio.hpp>
#include <boost/type_traits/is_integral.hpp>

#include <cryptopp/integer.h>

namespace assh
{

class ipacket;
class opacket;

class packet_exception : public std::exception
{
};
	
enum message_type : uint8
{
	msg_undefined,

	msg_disconnect = 1, msg_ignore, msg_unimplemented, msg_debug, msg_service_request, msg_service_accept,

	msg_kexinit = 20, msg_newkeys,

	msg_kex_dh_init = 30, msg_kex_dh_reply,
	msg_kex_dh_gex_group = 31, msg_kex_dh_gex_init, msg_kex_dh_gex_reply, msg_kex_dh_gex_request,

 	msg_userauth_request = 50, msg_userauth_failure, msg_userauth_success, msg_userauth_banner,

	msg_userauth_info_request = 60, msg_userauth_info_response,

	msg_global_request = 80, msg_request_success, msg_request_failure,

	msg_channel_open = 90, msg_channel_open_confirmation, msg_channel_open_failure,
	msg_channel_window_adjust, msg_channel_data, msg_channel_extended_data,
	msg_channel_eof, msg_channel_close, msg_channel_request, msg_channel_success,
	msg_channel_failure,
};

class opacket
{
  public:

  	friend bool operator==(const opacket&, const ipacket&);
	friend bool operator==(const ipacket&, const opacket&);

					opacket();
					opacket(message_type message);
					opacket(const opacket& rhs);
					opacket(opacket&& rhs);
	opacket&		operator=(const opacket& rhs);
	opacket&		operator=(opacket&& rhs);

	void			write(std::ostream& os, int blocksize) const;
	
					operator std::vector<uint8>() const	{ return m_data; }

	bool			empty() const						{ return m_data.empty() or static_cast<message_type>(m_data[0]) == msg_undefined; }
	std::size_t		size() const						{ return m_data.size(); }

	template<typename INT>
	opacket&		operator<<(INT v);
	opacket&		operator<<(const char* v);
	opacket&		operator<<(const std::string& v);
	opacket&		operator<<(const std::vector<std::string>& v);
	opacket&		operator<<(const char* v[]);
	opacket&		operator<<(const std::vector<byte>& v);
	opacket&		operator<<(const CryptoPP::Integer& v);
	opacket&		operator<<(const opacket& v);
	opacket&		operator<<(const ipacket& v);
	
	// for ranges:
	opacket&		operator<<(const std::pair<const char*,std::size_t>& v)
					{
						operator<<(v.second);
						m_data.insert(m_data.end(), reinterpret_cast<const uint8*>(v.first),
							reinterpret_cast<const uint8*>(v.first + v.second));
						return *this;
					}
	
  protected:
	std::vector<uint8>	m_data;
};

class ipacket
{
  public:
	friend class opacket;
  	friend bool operator==(const opacket&, const ipacket&);
	friend bool operator==(const ipacket&, const opacket&);

					ipacket();
					ipacket(const ipacket& rhs);
					ipacket(ipacket&& rhs);
					~ipacket();

	ipacket&		operator=(const ipacket& rhs);
	ipacket&		operator=(ipacket&& rhs);

	bool			complete();
	bool			empty();
	void			clear();
	void			strip_padding();
	
	size_t			size() const						{ return m_length; }
	
	void			append(const std::vector<uint8>& block);

	message_type	message() const						{ return m_message; }
					operator message_type() const		{ return m_message; }

					operator std::vector<uint8>() const	{ return std::vector<uint8>(m_data, m_data + m_length); }

	void			skip(uint32 bytes)					{ m_offset += bytes; }

	template<typename INT>
	ipacket&		operator>>(INT& v);
	ipacket&		operator>>(std::string& v);
	ipacket&		operator>>(std::vector<std::string>& v);
	ipacket&		operator>>(std::vector<byte>& v);
	ipacket&		operator>>(CryptoPP::Integer& v);
	ipacket&		operator>>(ipacket& v);
	ipacket&		operator>>(std::pair<const char*,std::size_t>& v);

  protected:
	message_type		m_message;
	uint8				m_padding;
	bool				m_owned;
	bool				m_complete;
	uint32				m_offset, m_length;
	uint8*				m_data;
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
	
	if (m_offset + sizeof(INT) > m_length)
		throw packet_exception();
	
	for (int i = sizeof(INT) - 1; i >= 0; --i)
		v = v << 8 | m_data[m_offset++];

	return *this;
}

bool operator==(const opacket&, const ipacket&);
bool operator==(const ipacket&, const opacket&);

}
