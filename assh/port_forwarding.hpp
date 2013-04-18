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

struct bound_port;
class basic_connection;

class port_forward_listener
{
  public:
				port_forward_listener(basic_connection& connection);
				~port_forward_listener();

	void		forward_port(
					const std::string& local_addr, uint16 local_port,
					const std::string& remote_addr, uint16 remote_port);
	void		forward_http(const std::string& local_addr, uint16 local_port);

	void		remove_port_forward(uint16 local_port);
	void		connection_closed();

	void		accept_failed(const boost::system::error_code& ec, bound_port* e);

  private:
				port_forward_listener(const port_forward_listener&);
	port_forward_listener&
				operator=(const port_forward_listener&);

	typedef std::list<bound_port*> bound_port_list;
	
	basic_connection&	m_connection;
	bound_port_list		m_bound_ports;
};

}
