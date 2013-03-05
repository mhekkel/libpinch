//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include <assh/config.hpp>

#include <boost/asio.hpp>

#include <assh/channel.hpp>
#include <assh/packet.hpp>

namespace assh
{

struct entry;
class basic_connection;

class port_forward_listener
{
  public:
				port_forward_listener(basic_connection& connection);
				~port_forward_listener();

	void		forward_port(
					const std::string& local_addr, uint16 local_port,
					const std::string& remote_addr, uint16 remote_port);

	void		remove_port_forward(uint16 local_port);
	void		connection_closed();

	void		accept_failed(const boost::system::error_code& ec, entry* e);

  private:
				port_forward_listener(const port_forward_listener&);
	port_forward_listener&
				operator=(const port_forward_listener&);

	typedef std::list<entry*>	entry_list;
	
	basic_connection&	m_connection;
	entry_list			m_entries;
};

// --------------------------------------------------------------------

class port_forwarding_channel : public channel
{
  public:

					port_forwarding_channel(basic_connection& inConnection,
						const std::string& remote_addr, uint16 remote_port);
					~port_forwarding_channel();

	boost::asio::ip::tcp::socket&
					get_socket()		{ return m_socket; }

  protected:

	virtual std::string
					channel_type() const						{ return "direct-tcpip"; }
	virtual void	fill_open_opacket(opacket& out);

	virtual void	setup(ipacket& in);
	virtual void	closed();

	virtual void	receive_data(const char* data, std::size_t size);

	void			receive_raw(const boost::system::error_code& ec, std::size_t bytes_received);
	

	boost::asio::streambuf				m_response;
	std::deque<boost::asio::streambuf*>	m_requests;
	boost::asio::ip::tcp::socket		m_socket;
	std::vector<uint8>					m_packet;
	std::string							m_remote_address;
	uint16								m_remote_port;
};

}
