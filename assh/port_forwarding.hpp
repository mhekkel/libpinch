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

class basic_connection;

class port_forward_listener
{
  public:
	port_forward_listener(basic_connection& connection);
	~port_forward_listener();

	void forward_port(
		const std::string& local_addr, uint16 local_port,
		const std::string& remote_addr, uint16 remote_port);
	void forward_socks5(const std::string& local_addr, uint16 local_port);

	void remove_port_forward(uint16 local_port);
	void connection_closed();

	//void accept_failed(const boost::system::error_code& ec, bound_port* e);

  private:
	port_forward_listener(const port_forward_listener&);
	port_forward_listener&
		operator=(const port_forward_listener&);

	//typedef std::list<bound_port*> bound_port_list;

	basic_connection& m_connection;
	//bound_port_list m_bound_ports;
};

// --------------------------------------------------------------------

class forwarding_channel : public channel
{
  public:
	forwarding_channel(basic_connection& inConnection, const std::string& remote_addr, uint16 remote_port);

	virtual std::string channel_type() const		{ return "direct-tcpip"; }
	virtual void fill_open_opacket(opacket& out);

	bool forwards_to(const std::string& host, uint16 port) const
	{
		return port == m_remote_port and host == m_remote_address;
	}

  protected:
	std::string m_remote_address;
	uint16 m_remote_port;
};

}
