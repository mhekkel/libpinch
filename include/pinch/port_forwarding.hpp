//        Copyright Maarten L. Hekkelman 2013-2021
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

/// \brief classes for forwarding connections

#include "pinch/channel.hpp"

#include <memory>

namespace pinch
{

// forward declaration
class bound_port;

/// \brief The port forward listener
///
/// Each connection can have a port forward listener. This class
/// takes care of listening to a local port and when a connection
/// comes in, this is forwarded over a new channel to the server.
class port_forward_listener
{
  public:
	/// \brief Constructor taking a connection
	port_forward_listener(std::shared_ptr<basic_connection> connection);

	/// \brief Destructor
	~port_forward_listener();

	/// \brief Directly forward incomming connections
	///
	/// \param local_port	The local port to listen to
	/// \param remote_addr	The address this connection to be forwarded to
	/// \param remote_port	The port this connection to be forwarded to
	void forward_port(uint16_t local_port, const std::string &remote_addr, uint16_t remote_port);

	/// \brief Create a SOCKS5 proxy
	///
	/// This creates a full SOCKS5 compatible proxy.
	///
	/// \param local_port	The local port to listen to
	void forward_socks5(uint16_t local_port);

	/// \brief remove the forwarded port
	void remove_port_forward(uint16_t local_port);

	/// \brief Handle the closing of a connection
	void connection_closed();

  private:
	port_forward_listener(const port_forward_listener &);
	port_forward_listener &
	operator=(const port_forward_listener &);

	std::shared_ptr<basic_connection> m_connection;
	std::vector<std::shared_ptr<bound_port>> m_bound_ports;
};

// --------------------------------------------------------------------

/// \brief Connect to a remote host/port directly
class forwarding_channel : public channel
{
  public:
	/// \brief Constructor
	///
	/// \param inConnection	The connection to use
	/// \param local_port	The port we communicate as being bound to locally
	/// \param remote_addr	The address this connection to be forwarded to
	/// \param remote_port	The port this connection to be forwarded to
	forwarding_channel(std::shared_ptr<basic_connection> inConnection,
		uint16_t local_port, const std::string &remote_addr, uint16_t remote_port);

	/// \brief Constructor
	///
	/// \param inConnection	The connection to use
	/// \param remote_addr	The address this connection to be forwarded to
	/// \param remote_port	The port this connection to be forwarded to
	forwarding_channel(std::shared_ptr<basic_connection> inConnection,
		const std::string &remote_addr, uint16_t remote_port)
		: forwarding_channel(inConnection, 80, remote_addr, remote_port)
	{
	}

	/// \brief Return the channel type, which is direct-tcpip for a forwarding channel
	virtual std::string channel_type() const { return "direct-tcpip"; }

	/// \brief Fill the opening packet with additional data
	virtual void fill_open_opacket(opacket &out);

	/// \brief Check if this forwarding channel is connected to \a host and \a port
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
