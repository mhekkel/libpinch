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
	for_each(m_entries.begin(), m_entries.end(),
		[](entry& e)
		{
			delete e.connection;
			e.connection = nullptr;
		});
}

void connection_pool::set_algorithm(algorithm alg, direction dir, const string& preferred)
{
	switch (alg)
	{
		case keyexchange:
			m_alg_kex = preferred;
			break;

		case encryption:
			if (dir != client2server)
				m_alg_enc_s2c = preferred;
			if (dir != server2client)
				m_alg_enc_c2s = preferred;
			break;
		
		case verification:
			if (dir != client2server)
				m_alg_ver_s2c = preferred;
			if (dir != server2client)
				m_alg_ver_c2s = preferred;
			break;
		
		case compression:
			if (dir != client2server)
				m_alg_cmp_s2c = preferred;
			if (dir != server2client)
				m_alg_cmp_c2s = preferred;
			break;
	}
}

void connection_pool::register_proxy(const string& destination_host, uint16 destination_port,
	const string& proxy_user, const string& proxy_host, uint16 proxy_port, const string& proxy_cmd)
{
	proxy p = { destination_host, destination_port, proxy_cmd, proxy_user, proxy_host, proxy_port };
	proxy_list::iterator pi = find(m_proxies.begin(), m_proxies.end(), p);
	if (pi == m_proxies.end())
		m_proxies.push_back(p);
	else
		*pi = p;
}

basic_connection& connection_pool::get(const string& user, const string& host, uint16 port)
{
	basic_connection* result = nullptr;
	
	foreach (auto& e, m_entries)
	{
		if (e.user == user and e.host == host and e.port == port)
		{
			result = e.connection;
			break;
		}
	}
	
	if (result == nullptr)
	{
		foreach (auto& p, m_proxies)
		{
			if (p.destination_host == host and p.destination_port == port)
			{
				result = new proxied_connection(get(p.proxy_user, p.proxy_host, p.proxy_port), p.proxy_cmd, user, host, port);
				break;
			}
		}
		
		if (result == nullptr)
			result = new connection(m_io_service, user, host, port);
			
		entry e = { user, host, port, result };
		m_entries.push_back(e);

		if (not m_alg_kex.empty())		result->set_algorithm(keyexchange,	client2server, m_alg_kex);
		if (not m_alg_enc_c2s.empty())	result->set_algorithm(encryption,	client2server, m_alg_enc_c2s);
		if (not m_alg_ver_c2s.empty())	result->set_algorithm(verification,	client2server, m_alg_ver_c2s);
		if (not m_alg_cmp_c2s.empty())	result->set_algorithm(compression,	client2server, m_alg_cmp_c2s);
		if (not m_alg_enc_s2c.empty())	result->set_algorithm(encryption,	server2client, m_alg_enc_s2c);
		if (not m_alg_ver_s2c.empty())	result->set_algorithm(verification,	server2client, m_alg_ver_s2c);
		if (not m_alg_cmp_s2c.empty())	result->set_algorithm(compression,	server2client, m_alg_cmp_s2c);
	}

	return *result;
}
	
basic_connection& connection_pool::get(const string& user, const string& host, uint16 port,
	const string& proxy_user, const string& proxy_host, uint16 proxy_port, const string& proxy_cmd)
{
	basic_connection* result = nullptr;
	
	foreach (auto& e, m_entries)
	{
		if (e.user == user and e.host == host and e.port == port and
			dynamic_cast<proxied_connection*>(e.connection) != nullptr)
		{
			result = e.connection;
			break;
		}
	}
	
	if (result == nullptr)
	{
		basic_connection& proxy = get(proxy_user, proxy_host, proxy_port);
		result = new proxied_connection(proxy, proxy_cmd, user, host, port);

		entry e = { user, host, port, result };
		m_entries.push_back(e);
	
		if (not m_alg_kex.empty())		result->set_algorithm(keyexchange, client2server, m_alg_kex);
		if (not m_alg_enc_c2s.empty())	result->set_algorithm(encryption, client2server, m_alg_enc_c2s);
		if (not m_alg_ver_c2s.empty())	result->set_algorithm(verification, client2server, m_alg_ver_c2s);
		if (not m_alg_cmp_c2s.empty())	result->set_algorithm(compression, client2server, m_alg_cmp_c2s);
		if (not m_alg_enc_s2c.empty())	result->set_algorithm(encryption, server2client, m_alg_enc_s2c);
		if (not m_alg_ver_s2c.empty())	result->set_algorithm(verification, server2client, m_alg_ver_s2c);
		if (not m_alg_cmp_s2c.empty())	result->set_algorithm(compression, server2client, m_alg_cmp_s2c);
	}
	
	return *result;
}
	
void connection_pool::disconnect_all()
{
	m_io_service.stop();

	for_each(m_entries.begin(), m_entries.end(),
		[](entry& e)
		{
			e.connection->disconnect();
		});
}

}
