//        Copyright Maarten L. Hekkelman 2013-2021
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include <pinch/pinch.hpp>

#include <pinch/channel.hpp>

namespace pinch
{

class basic_connection;
class bound_port;

class port_forward_listener
{
  public:
	port_forward_listener(std::shared_ptr<basic_connection> connection);
	~port_forward_listener();

	void forward_port(uint16_t local_port, const std::string &remote_addr, uint16_t remote_port);
	void forward_socks5(uint16_t local_port);

	void remove_port_forward(uint16_t local_port);
	void connection_closed();

	//void accept_failed(const boost::system::error_code& ec, bound_port* e);

  private:
	port_forward_listener(const port_forward_listener &);
	port_forward_listener &
	operator=(const port_forward_listener &);

	std::shared_ptr<basic_connection> m_connection;
	std::vector<std::shared_ptr<bound_port>> m_bound_ports;
};

// --------------------------------------------------------------------

class forwarding_channel : public channel
{
  public:
	forwarding_channel(std::shared_ptr<basic_connection> inConnection,
		uint16_t local_port, const std::string &remote_addr, uint16_t remote_port);

	forwarding_channel(std::shared_ptr<basic_connection> inConnection,
		const std::string &remote_addr, uint16_t remote_port)
		: forwarding_channel(inConnection, 80, remote_addr, remote_port)
	{
	}

	virtual std::string channel_type() const { return "direct-tcpip"; }
	virtual void fill_open_opacket(opacket &out);

	bool forwards_to(const std::string &host, uint16_t port) const
	{
		return port == m_remote_port and host == m_remote_address;
	}

  protected:
	std::string m_remote_address;
	uint16_t m_remote_port;
	uint16_t m_local_port;
};

} // namespace pinch
