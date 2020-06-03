//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <assh/config.hpp>

#include <list>

#include <boost/foreach.hpp>
#define foreach BOOST_FOREACH

#include <assh/proxy_cmd.hpp>
#include <assh/connection_pool.hpp>

using namespace std;

namespace assh
{

// --------------------------------------------------------------------

connection_pool::connection_pool(boost::asio::io_service& io_service)
	: m_io_service(io_service)
{
}

connection_pool::~connection_pool()
{
	// for_each(m_entries.begin(), m_entries.end(),
	// 	[](entry& e)
	// 	{
	// 		e.connection.reset(nullptr);
	// 	});
}

void connection_pool::set_algorithm(algorithm alg, direction dir, const string& preferred)
{
	switch (alg)
	{
		case algorithm::keyexchange:
			m_alg_kex = preferred;
			break;

		case algorithm::encryption:
			if (dir != direction::c2s)
				m_alg_enc_s2c = preferred;
			if (dir != direction::s2c)
				m_alg_enc_c2s = preferred;
			break;
		
		case algorithm::verification:
			if (dir != direction::c2s)
				m_alg_ver_s2c = preferred;
			if (dir != direction::s2c)
				m_alg_ver_c2s = preferred;
			break;
		
		case algorithm::compression:
			if (dir != direction::c2s)
				m_alg_cmp_s2c = preferred;
			if (dir != direction::s2c)
				m_alg_cmp_c2s = preferred;
			break;
	}

	for_each(m_entries.begin(), m_entries.end(),
		[=](entry& e)
		{
			e.connection->set_algorithm(alg, dir, preferred);
		});
}

void connection_pool::register_proxy(const string& destination_host, int16_t destination_port,
	const string& proxy_user, const string& proxy_host, int16_t proxy_port, const string& proxy_cmd)
{
	proxy p = { destination_host, destination_port, proxy_cmd, proxy_user, proxy_host, proxy_port };
	proxy_list::iterator pi = find(m_proxies.begin(), m_proxies.end(), p);
	if (pi == m_proxies.end())
		m_proxies.push_back(p);
	else
		*pi = p;
}

std::shared_ptr<basic_connection> connection_pool::get(const string& user, const string& host, int16_t port)
{
	std::shared_ptr<basic_connection> result;
	
	for (auto& e: m_entries)
	{
		if (e.user == user and e.host == host and e.port == port)
		{
			result = e.connection;
			break;
		}
	}
	
	if (result == nullptr)
	{
	// 	for (auto& p: m_proxies)
	// 	{
	// 		if (p.destination_host == host and p.destination_port == port)
	// 		{
	// 			result.reset(new proxied_connection(get(p.proxy_user, p.proxy_host, p.proxy_port), p.proxy_cmd, user, host, port));
	// 			break;
	// 		}
	// 	}
		
		if (result == nullptr)
			result = std::make_shared<connection>(m_io_service, user, host, port);
			
		entry e = { user, host, port, result };
		m_entries.push_back(e);

		if (not m_alg_kex.empty())		result->set_algorithm(algorithm::keyexchange,	direction::c2s, m_alg_kex);
		if (not m_alg_enc_c2s.empty())	result->set_algorithm(algorithm::encryption,	direction::c2s, m_alg_enc_c2s);
		if (not m_alg_ver_c2s.empty())	result->set_algorithm(algorithm::verification,	direction::c2s, m_alg_ver_c2s);
		if (not m_alg_cmp_c2s.empty())	result->set_algorithm(algorithm::compression,	direction::c2s, m_alg_cmp_c2s);
		if (not m_alg_enc_s2c.empty())	result->set_algorithm(algorithm::encryption,	direction::s2c, m_alg_enc_s2c);
		if (not m_alg_ver_s2c.empty())	result->set_algorithm(algorithm::verification,	direction::s2c, m_alg_ver_s2c);
		if (not m_alg_cmp_s2c.empty())	result->set_algorithm(algorithm::compression,	direction::s2c, m_alg_cmp_s2c);
	}

	return result;
}
	
// std::shared_ptr<basic_connection> connection_pool::get(const string& user, const string& host, int16_t port,
// 	const string& proxy_user, const string& proxy_host, int16_t proxy_port, const string& proxy_cmd)
// {
// 	std::shared_ptr<basic_connection> result;
	
// 	for (auto& e: m_entries)
// 	{
// 		if (e.user == user and e.host == host and e.port == port and
// 			dynamic_cast<proxied_connection*>(e.connection.get()) != nullptr)
// 		{
// 			result = e.connection;
// 			break;
// 		}
// 	}
	
// 	if (result == nullptr)
// 	{
// 		std::shared_ptr<basic_connection> proxy = get(proxy_user, proxy_host, proxy_port);
// 		result.reset(new proxied_connection(proxy, proxy_cmd, user, host, port));

// 		entry e = { user, host, port, result };
// 		m_entries.push_back(e);
	
// 		if (not m_alg_kex.empty())		result->set_algorithm(algorithm::keyexchange,	direction::c2s, m_alg_kex);
// 		if (not m_alg_enc_c2s.empty())	result->set_algorithm(algorithm::encryption,	direction::c2s, m_alg_enc_c2s);
// 		if (not m_alg_ver_c2s.empty())	result->set_algorithm(algorithm::verification,	direction::c2s, m_alg_ver_c2s);
// 		if (not m_alg_cmp_c2s.empty())	result->set_algorithm(algorithm::compression,	direction::c2s, m_alg_cmp_c2s);
// 		if (not m_alg_enc_s2c.empty())	result->set_algorithm(algorithm::encryption,	direction::s2c, m_alg_enc_s2c);
// 		if (not m_alg_ver_s2c.empty())	result->set_algorithm(algorithm::verification,	direction::s2c, m_alg_ver_s2c);
// 		if (not m_alg_cmp_s2c.empty())	result->set_algorithm(algorithm::compression,	direction::s2c, m_alg_cmp_s2c);
// 	}
	
// 	return result;
// }
	
void connection_pool::disconnect_all()
{
	m_io_service.stop();

	for_each(m_entries.begin(), m_entries.end(),
		[](entry& e)
		{
			e.connection->disconnect();
		});
}

bool connection_pool::has_open_connections()
{
	bool connection_open = false;

	for (auto& e: m_entries)
	{
		if (e.connection->is_connected())
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

	for (auto& e: m_entries)
	{
		if (e.connection->is_connected() and e.connection->has_open_channels())
		{
			channel_open = true;
			break;
		}
	}

	return channel_open;
}

}
