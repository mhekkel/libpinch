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

void connection_pool::register_proxy(const string& destination_host, uint16 destination_port,
	const string& proxy_cmd, const string& proxy_user, const string& proxy_host, uint16 proxy_port)
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
