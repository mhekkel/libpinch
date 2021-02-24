//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include <assh/config.hpp>

#include <list>

#include <boost/asio/io_service.hpp>
#include <assh/connection.hpp>

namespace assh
{

	class connection_pool
	{
	public:
		connection_pool(boost::asio::io_service &io_service);
		~connection_pool();

		// set algorithms to use by connections created by this pool
		void set_algorithm(algorithm alg, direction dir, const std::string &preferred);

		std::shared_ptr<basic_connection> get(const std::string &user, const std::string &host, int16_t port);

		// get a proxied connection
		std::shared_ptr<basic_connection> get(const std::string &user, const std::string &host, int16_t port,
							  const std::string &proxy_user, const std::string &proxy_host,
							  int16_t proxy_port, const std::string &proxy_cmd);

		// register a default proxy for a connection
		void register_proxy(const std::string &destination_host, int16_t destination_port,
							const std::string &proxy_user, const std::string &proxy_host,
							int16_t proxy_port, const std::string &proxy_cmd);

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
			int16_t port;
			std::shared_ptr<basic_connection> connection;
		};

		typedef std::list<entry> entry_list;

		struct proxy
		{
			std::string destination_host;
			int16_t destination_port;
			std::string proxy_cmd;
			std::string proxy_user;
			std::string proxy_host;
			int16_t proxy_port;

			bool operator==(const proxy &rhs) const
			{
				return destination_host == rhs.destination_host and
					   destination_port == rhs.destination_port;
			}
		};

		typedef std::list<proxy> proxy_list;

		boost::asio::io_service &m_io_service;
		entry_list m_entries;
		proxy_list m_proxies;

		std::string m_alg_kex,
			m_alg_enc_c2s, m_alg_ver_c2s, m_alg_cmp_c2s,
			m_alg_enc_s2c, m_alg_ver_s2c, m_alg_cmp_s2c;
	};

} // namespace assh
