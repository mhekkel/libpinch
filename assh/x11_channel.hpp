//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include <assh/config.hpp>

#include <boost/format.hpp>
#include <boost/function.hpp>
#include <boost/asio.hpp>

#include <assh/channel.hpp>
#include <assh/packet.hpp>

namespace assh
{

// --------------------------------------------------------------------

class x11_channel : public channel
{
  public:

					x11_channel(basic_connection& inConnection);
					~x11_channel();

  protected:

	virtual void	setup(ipacket& in);
	virtual void	closed();

	virtual void	receive_data(const char* data, std::size_t size);
	bool			check_validation();

	void			receive_raw(const boost::system::error_code& ec, std::size_t bytes_received);
	

	boost::asio::streambuf				m_response;
	std::deque<boost::asio::streambuf*>	m_requests;
	boost::asio::ip::tcp::socket		m_socket;
	bool								m_verified;
	std::string							m_auth_protocol, m_auth_data;
	std::vector<uint8>					m_packet;
};

}
