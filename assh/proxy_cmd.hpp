//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include <assh/config.hpp>
#include <assh/connection.hpp>

namespace assh
{

class proxied_connection : public basic_connection
{
  public:

							proxied_connection(basic_connection& proxy,
								const std::string& nc_cmd,
								const std::string& user,
								const std::string& host, uint16 port = 22);

							~proxied_connection();

	boost::asio::io_service&
							get_io_service() 
							{
								return m_proxy.get_io_service();
							}

  protected:

	virtual void			start_handshake();

	virtual void			async_write_int(boost::asio::streambuf* request, basic_write_op* op);
	virtual void			async_read_version_string();
	virtual void			async_read(uint32 at_least);

  private:
	basic_connection&		m_proxy;
	class proxy_channel*	m_channel;
};

}
