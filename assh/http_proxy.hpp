//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include <boost/tr1/memory.hpp>

#include <assh/config.hpp>

#include <assh/port_forwarding.hpp>

#include <zeep/http/request.hpp>
#include <zeep/http/reply.hpp>
#include <zeep/http/message_parser.hpp>
#include <zeep/http/template_processor.hpp>

namespace assh {
namespace http_proxy {

class proxy_connection;
class proxy_channel;

enum log_options
{
	e_log_request =	1 << 0,
	e_log_debug =	1 << 1
};

class server : public std::tr1::enable_shared_from_this<server>,
	public zeep::http::template_processor
{
  public:
	server(basic_connection& connection, uint32 log_flags = 0);
	
	void listen(uint16 port);
	void set_log_flags(uint32 log_flags);

	void handle_request(zeep::http::request& request,
		zeep::http::reply& reply, std::shared_ptr<proxy_connection> conn);

	void log_request(const std::string& client,
		const zeep::http::request& req, const zeep::http::reply& rep,
		const boost::posix_time::ptime& start);
	void log_error(const std::exception& e);
	void log_error(const boost::system::error_code& ec);

	void channel_closed(proxy_channel* channel);

  private:

	virtual void load_template(const std::string& file, zeep::xml::document& doc);
	void handle_accept(const boost::system::error_code& ec);

	basic_connection& m_connection;
	std::shared_ptr<proxy_connection> m_new_connection;
	std::shared_ptr<std::ostream> m_log;
	std::shared_ptr<boost::asio::ip::tcp::acceptor> m_acceptor;
	std::list<std::shared_ptr<channel>> m_channels;
	uint32 m_log_flags;
};

}
}
