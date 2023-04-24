//        Copyright Maarten L. Hekkelman 2013-2021
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

/// \file connection_pool.hpp
/// Definition of the connection_pool class
///
/// A connection_pool can be used to keep the number of connections
/// limited. Each connection is stored and can be reused.
///
/// Connections are uniquely defined by their user/host/port combination.

#include "pinch/pinch.hpp"

#include "pinch/channel.hpp"

namespace pinch
{

/// \brief The connection_pool class.
///
/// You should probably have only one instance of this class,
/// however it is not a singleton. yet?

class connection_pool
{
  public:
	/// \brief constructor
	///
	/// \param io_context	The boost io_context to use
	connection_pool(asio::io_context &io_context);

	/// \brief destructor
	~connection_pool();

	/// \brief Return a connection for a user/host/port combination
	///
	/// \param user		The username to use when authenticating
	/// \param host		The hostname or ip address of the server
	/// \param port		The port to connect to
	std::shared_ptr<basic_connection> get(const std::string &user, const std::string &host, uint16_t port = 22);

	/// \brief Return a proxied connection for a user/host/port combination via a proxy
	///
	/// \param user			The username to use when authenticating
	/// \param host			The hostname or ip address of the server
	/// \param port			The port to connect to
	/// \param proxy_user	The username to use when authenticating to the proxy host
	/// \param proxy_host	The hostname or ip address of the proxy server
	/// \param proxy_port	The port at the proxy server to connect to
	/// \param proxy_cmd	The proxy command to use, e.g. /usr/bin/netcat. Leave empty to use direct-tcpip
	std::shared_ptr<basic_connection> get(const std::string &user, const std::string &host, uint16_t port,
		const std::string &proxy_user, const std::string &proxy_host,
		uint16_t proxy_port, const std::string &proxy_cmd = {});

	/// \brief Register a default proxy for a connection
	///
	/// \param destination_host	The hostname or ip address of the server
	/// \param destination_port	The port to connect to
	/// \param proxy_user		The username to use when authenticating to the proxy host
	/// \param proxy_host		The hostname or ip address of the proxy server
	/// \param proxy_port		The port at the proxy server to connect to
	/// \param proxy_cmd	The proxy command to use, e.g. /usr/bin/netcat. Leave empty to use direct-tcpip
	void register_proxy(const std::string &destination_host, uint16_t destination_port,
		const std::string &proxy_user, const std::string &proxy_host,
		uint16_t proxy_port, const std::string &proxy_cmd);

	/// \brief Close all connections
	void disconnect_all();

	/// \brief Are there connections open?
	bool has_open_connections();

	/// \brief Are there any channels still open?
	bool has_open_channels();

  private:
	connection_pool(const connection_pool &);
	connection_pool &operator=(const connection_pool &);

	struct entry
	{
		std::string user;
		std::string host;
		uint16_t port;
		std::shared_ptr<basic_connection> connection;
	};

	using entry_list = std::list<entry>;

	struct proxy
	{
		std::string destination_host;
		uint16_t destination_port;
		std::string proxy_cmd;
		std::string proxy_user;
		std::string proxy_host;
		uint16_t proxy_port;

		bool operator==(const proxy &rhs) const
		{
			return destination_host == rhs.destination_host and
			       destination_port == rhs.destination_port;
		}
	};

	using proxy_list = std::list<proxy>;

	asio::io_context &m_io_context;
	entry_list m_entries;
	proxy_list m_proxies;
};

} // namespace pinch
