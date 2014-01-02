//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include <assh/config.hpp>

#include <assh/port_forwarding.hpp>

#include <zeep/http/request.hpp>
#include <zeep/http/reply.hpp>
#include <zeep/http/request_parser.hpp>

namespace assh
{

// --------------------------------------------------------------------

class http_proxy_channel : public basic_forwarding_channel
{
  public:

	http_proxy_channel(basic_connection& inConnection);

	virtual void start();
	virtual void opened();
	virtual void closed();

  private:

	void handle_read_server(const boost::system::error_code& ec, size_t bytes_transferred);
	void handle_write_server(const boost::system::error_code& ec);

	void handle_read_client(const boost::system::error_code& ec, size_t bytes_transferred);
	void reply_error();

	void handle_request();
	void forward_request();

	zeep::http::request_parser m_request_parser;
	boost::array<char,8192> m_buffer;						
	zeep::http::request m_request;
	zeep::http::reply m_reply;
};

}
