//        Copyright Maarten L. Hekkelman 2013-2021
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)


#include "pinch/connection_pool.hpp"

namespace pinch
{

// --------------------------------------------------------------------

connection_pool::connection_pool(asio_ns::io_context &io_context)
	: m_io_context(io_context)
{
}

connection_pool::~connection_pool()
{
	for (auto &e : m_entries)
		e.connection.reset();
}

void connection_pool::register_proxy(const std::string &destination_host, uint16_t destination_port,
	const std::string &proxy_user, const std::string &proxy_host, uint16_t proxy_port, const std::string &proxy_cmd)
{
	proxy p = {destination_host, destination_port, proxy_cmd, proxy_user, proxy_host, proxy_port};
	proxy_list::iterator pi = find(m_proxies.begin(), m_proxies.end(), p);
	if (pi == m_proxies.end())
		m_proxies.push_back(p);
	else
		*pi = p;
}

std::shared_ptr<basic_connection> connection_pool::get(const std::string &user, const std::string &host, uint16_t port)
{
	std::shared_ptr<basic_connection> result;

	for (auto &e : m_entries)
	{
		if (e.user == user and e.host == host and e.port == port)
		{
			result = e.connection;
			break;
		}
	}

	if (result == nullptr)
	{
		result = std::make_shared<connection>(m_io_context, user, host, port);

		entry e = {user, host, port, result};
		m_entries.push_back(e);
	}

	return result;
}

std::shared_ptr<basic_connection> connection_pool::get(const std::string &user, const std::string &host, uint16_t port,
	const std::string &proxy_user, const std::string &proxy_host, uint16_t proxy_port, const std::string &proxy_cmd)
{
	std::shared_ptr<basic_connection> result;

	for (auto &e : m_entries)
	{
		if (e.user == user and e.host == host and e.port == port and
			dynamic_cast<proxied_connection *>(e.connection.get()) != nullptr)
		{
			result = e.connection;
			break;
		}
	}

	if (result == nullptr)
	{
		std::shared_ptr<basic_connection> proxy = get(proxy_user, proxy_host, proxy_port);

		if (proxy_cmd.empty())
			result.reset(new proxied_connection(proxy, user, host, port));
		else
			result.reset(new proxied_connection(proxy, proxy_cmd, user, host, port));

		entry e = {user, host, port, result};
		m_entries.push_back(e);
	}

	return result;
}

void connection_pool::disconnect_all()
{
	m_io_context.stop();

	for (auto &e : m_entries)
		e.connection->close();
}

bool connection_pool::has_open_connections()
{
	bool connection_open = false;

	for (auto &e : m_entries)
	{
		if (e.connection->is_open())
		{
			connection_open = true;
			break;
		}
	}

	return connection_open;
}

bool connection_pool::has_open_channels()
{
	bool channel_open = false;

	for (auto &e : m_entries)
	{
		if (e.connection->is_open() and e.connection->has_open_channels())
		{
			channel_open = true;
			break;
		}
	}

	return channel_open;
}

} // namespace pinch
