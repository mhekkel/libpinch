//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include <pinch/pinch.hpp>

#include <list>

#include <boost/asio/io_service.hpp>
#include <pinch/channel.hpp>

namespace pinch
{

class connection_pool
{
  public:
	connection_pool(boost::asio::io_context &io_context);
	~connection_pool();

	// set algorithms to use by connections created by this pool
	void set_algorithm(algorithm alg, direction dir, const std::string &preferred);

	std::shared_ptr<basic_connection> get(const std::string &user, const std::string &host, uint16_t port);

	// get a proxied connection
	std::shared_ptr<basic_connection> get(const std::string &user, const std::string &host, uint16_t port,
						  const std::string &proxy_user, const std::string &proxy_host,
						  uint16_t proxy_port, const std::string &proxy_cmd = {});

	// register a default proxy for a connection
	void register_proxy(const std::string &destination_host, uint16_t destination_port,
						const std::string &proxy_user, const std::string &proxy_host,
						uint16_t proxy_port, const std::string &proxy_cmd);

	void disconnect_all();
	bool has_open_connections();
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

	boost::asio::io_context &m_io_context;
	entry_list m_entries;
	proxy_list m_proxies;

	std::string m_alg_kex,
		m_alg_enc_c2s, m_alg_ver_c2s, m_alg_cmp_c2s,
		m_alg_enc_s2c, m_alg_ver_s2c, m_alg_cmp_s2c;
};

} // namespace pinch
