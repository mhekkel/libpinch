//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <assh/config.hpp>

#include <fstream>

#include <boost/bind.hpp>
#include <boost/foreach.hpp>
#define foreach BOOST_FOREACH
#include <boost/lexical_cast.hpp>
#include <boost/regex.hpp>
#include <boost/array.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/date_time/local_time/local_time.hpp>
#include <boost/foreach.hpp>
#define foreach BOOST_FOREACH

#include <assh/http_proxy.hpp>
#include <assh/connection.hpp>

#include <zeep/http/server.hpp>
#include <zeep/http/message_parser.hpp>

using namespace std;
namespace ip = boost::asio::ip;
namespace zh = zeep::http;
namespace ba = boost::algorithm;

namespace assh {
namespace http_proxy {

using namespace boost::posix_time;

// --------------------------------------------------------------------

class proxy_connection : public std::tr1::enable_shared_from_this<proxy_connection>
{
  public:
	proxy_connection(basic_connection& ssh_connection, shared_ptr<server> proxy)
		: m_ssh_connection(ssh_connection), m_proxy(proxy), m_socket(m_ssh_connection.get_io_service()) {}

	void start();
	void reply_with_error(zh::status_type err, const string& message);
	void reply();

	boost::asio::ip::tcp::socket& get_socket() { return m_socket; }
	
	zh::reply& get_reply() { return m_reply; }
	zh::request& get_request() { return m_request; }

  private:

	void handle_read(const boost::system::error_code& ec, size_t bytes_transferred);
	void handle_write(const boost::system::error_code& ec);
	
	basic_connection& m_ssh_connection;
	shared_ptr<server> m_proxy;
	boost::asio::ip::tcp::socket m_socket;
	zh::request_parser m_request_parser;
	boost::array<char,8192> m_buffer;
	zh::request m_request;
	zh::reply m_reply;
	bool m_keep_alive;
	ptime m_start;
};

void proxy_connection::start()
{
	m_request = zh::request();	// reset
	
	m_request.local_address =
		boost::lexical_cast<string>(m_socket.local_endpoint().address());
	m_request.local_port = m_socket.local_endpoint().port();
	
	m_socket.async_read_some(boost::asio::buffer(m_buffer),
		boost::bind(&proxy_connection::handle_read, shared_from_this(),
			boost::asio::placeholders::error,
			boost::asio::placeholders::bytes_transferred));
}

void proxy_connection::handle_read(
	const boost::system::error_code& ec, size_t bytes_transferred)
{
	if (not ec)
	{
		size_t consumed = 0;
		while (consumed < bytes_transferred)
		{
			boost::tribool result;
			size_t used;
	
			tr1::tie(result, used) = m_request_parser.parse(
				m_request, m_buffer.data() + consumed, bytes_transferred - consumed);
			consumed += used;
	
			if (result)
			{
				m_request_parser.reset();
				m_start = second_clock::local_time();

				m_reply.set_version(m_request.http_version_major, m_request.http_version_minor);
				m_keep_alive = m_request.http_version_minor >= 1 and
					m_request.get_header("Connection") == "keep-alive";
				m_proxy->handle_request(m_request, m_reply, shared_from_this());
			}
			else if (not result)
			{
				m_keep_alive = false;
				reply_with_error(zh::bad_request, "");
			}
			else
			{
				m_socket.async_read_some(boost::asio::buffer(m_buffer),
					boost::bind(&proxy_connection::handle_read, shared_from_this(),
						boost::asio::placeholders::error,
						boost::asio::placeholders::bytes_transferred));
			}
		}
	}
}

void proxy_connection::reply_with_error(zh::status_type err, const string& message)
{
	m_reply.set_content(message, "text/plain");
	m_reply.set_status(err);
	
	reply();
}

void proxy_connection::reply()
{
	string client;
	
	try		// asking for the remote endpoint address failed sometimes
			// causing aborting exceptions, so I moved it here.
	{
		boost::asio::ip::address addr = m_socket.remote_endpoint().address();
		client = boost::lexical_cast<string>(addr);
	}
	catch (...)
	{
		client = "unknown";
	}

	m_proxy->log_request(client, m_request, m_reply, m_start);

	vector<boost::asio::const_buffer> buffers;
	m_reply.to_buffers(buffers);

	boost::asio::async_write(m_socket, buffers,
		boost::bind(&proxy_connection::handle_write, shared_from_this(),
			boost::asio::placeholders::error));
}

void proxy_connection::handle_write(const boost::system::error_code& ec)
{
	if (not ec)
	{
		vector<boost::asio::const_buffer> buffers;
		
		if (m_reply.data_to_buffers(buffers))
		{
			boost::asio::async_write(m_socket, buffers,
				boost::bind(&proxy_connection::handle_write, shared_from_this(),
					boost::asio::placeholders::error));
		}
		else if (m_keep_alive)
		{
			m_request_parser.reset();
			m_request = zh::request();
			m_reply = zh::reply();

			m_socket.async_read_some(boost::asio::buffer(m_buffer),
				boost::bind(&proxy_connection::handle_read, shared_from_this(),
					boost::asio::placeholders::error,
					boost::asio::placeholders::bytes_transferred));
		}
		else
			m_socket.close();
	}
}

// --------------------------------------------------------------------

class proxy_channel : public channel, public enable_shared_from_this<proxy_channel>
{
  public:
	proxy_channel(basic_connection& inConnection,
		const std::string& remote_addr, uint16 remote_port,
		shared_ptr<server> proxy)
		: channel(inConnection), m_proxy(proxy)
		, m_remote_address(remote_addr), m_remote_port(remote_port) {}

	void process_request(shared_ptr<proxy_connection> proxy_connection);

	virtual string channel_type() const				{ return "direct-tcpip"; }
	virtual void fill_open_opacket(opacket& out);

	const string& remote_address() const			{ return m_remote_address; }
	uint16 remote_port() const						{ return m_remote_port; }

  private:

	void handle_write(const boost::system::error_code& ec, shared_ptr<proxy_connection> conn);
	void handle_read(const boost::system::error_code& ec, size_t size, shared_ptr<proxy_connection> conn);

	string m_remote_address;
	uint16 m_remote_port;
	shared_ptr<server> m_proxy;
	boost::array<char,8192> m_buffer;
	zh::reply_parser m_reply_parser;
};

void proxy_channel::fill_open_opacket(opacket& out)
{
	channel::fill_open_opacket(out);

	//boost::asio::ip::address originator = get_socket().remote_endpoint().address();
	//string originator_address = boost::lexical_cast<string>(originator);
	//uint16 originator_port = get_socket().remote_endpoint().port();
	string originator_address = "127.0.0.1";
	uint16 originator_port = 80;

	out << m_remote_address << uint32(m_remote_port) << originator_address << uint32(originator_port);
}

void proxy_channel::process_request(shared_ptr<proxy_connection> proxy_connection)
{
	m_reply_parser.reset();
	
	boost::asio::streambuf* buffer = new boost::asio::streambuf;

	iostream out(buffer);
	out << proxy_connection->get_request();

	shared_ptr<proxy_channel> self(shared_from_this());

	boost::asio::async_write(*this, *buffer,
		[self, buffer, proxy_connection](const boost::system::error_code& ec, size_t s)
	{
		delete buffer;
		self->handle_write(ec, proxy_connection);
	});
}

void proxy_channel::handle_write(const boost::system::error_code& ec, shared_ptr<proxy_connection> conn)
{
	if (ec)
		conn->reply_with_error(/*ec*/ zh::internal_server_error, "");
	else
	{
		boost::asio::async_read(*this, boost::asio::buffer(m_buffer),
			boost::asio::transfer_at_least(1),
			boost::bind(&proxy_channel::handle_read, shared_from_this(),
				boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred, conn));
	}
}

void proxy_channel::handle_read(const boost::system::error_code& ec, size_t bytes_transferred,
	shared_ptr<proxy_connection> conn)
{
	if (ec)
		conn->reply_with_error(/*ec*/ zh::internal_server_error, "");
	else
	{
		boost::tribool result;
		size_t used;

		tr1::tie(result, used) = m_reply_parser.parse(
			conn->get_reply(), m_buffer.data(), bytes_transferred);

		if (result)
		{
			// we have a valid and complete reply
			conn->reply();
			close();
		}
		else if (not result)
		{
			// invalid reply
			conn->reply_with_error(zh::internal_server_error, "");
			close();
		}
		else
		{
			boost::asio::async_read(*this, boost::asio::buffer(m_buffer),
				boost::asio::transfer_at_least(1),
				boost::bind(&proxy_channel::handle_read, shared_from_this(),
					boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred, conn));
		}
	}
}

// --------------------------------------------------------------------

server::server(basic_connection& ssh_connection)
	: m_connection(ssh_connection)
	, m_log_flags(e_log_request)
{
	using namespace boost::local_time;

	m_log.reset(new ofstream("proxy.log", ios::app | ios::binary));

	local_time_facet* lf(new local_time_facet("[%d/%b/%Y:%H:%M:%S %z]"));
	m_log->imbue(locale(cout.getloc(), lf));
}

void server::listen(uint16 port)
{
	*m_log << "Starting proxy service" << endl;

	string address = "0.0.0.0";
	
	m_acceptor.reset(new boost::asio::ip::tcp::acceptor(m_connection.get_io_service()));
	m_new_connection.reset(new proxy_connection(m_connection, shared_from_this()));

	boost::asio::ip::tcp::resolver resolver(m_connection.get_io_service());
	boost::asio::ip::tcp::resolver::query query(address, boost::lexical_cast<string>(port));
	boost::asio::ip::tcp::endpoint endpoint = *resolver.resolve(query);

	m_acceptor->open(endpoint.protocol());
	m_acceptor->set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
	m_acceptor->bind(endpoint);
	m_acceptor->listen();
	m_acceptor->async_accept(m_new_connection->get_socket(),
		boost::bind(&server::handle_accept, this, boost::asio::placeholders::error));
}

void server::handle_accept(const boost::system::error_code& ec)
{
	if (not ec)
	{
		m_new_connection->start();
		m_new_connection.reset(new proxy_connection(m_connection, shared_from_this()));
		m_acceptor->async_accept(m_new_connection->get_socket(),
			boost::bind(&server::handle_accept, this, boost::asio::placeholders::error));
	}
}

void server::handle_request(zh::request& request, zh::reply& reply, shared_ptr<proxy_connection> conn)
{
	try	// do the actual work.
	{
		if (request.method != "OPTIONS" and request.method != "HEAD" and request.method != "POST" and
			request.method != "GET" and request.method != "PUT" and request.method != "DELETE" and
			request.method != "TRACE")
			throw logic_error("invalid method");

		string host = request.get_header("Host");
		uint16 port = 80;
		
		boost::regex re("^(?:https?://)?(?:([-$_.+!*'(),[:alnum:];?&=]+)(?::([-$_.+!*'(),[:alnum:];?&=]+))?@)?([-[:alnum:].]+)(?::(\\d+))?(/.*)");
		boost::smatch m;

		if (not boost::regex_match(request.uri, m, re))
			throw logic_error("invalid request");

		if (host.empty())
		{
			if (m[3].matched)
				host = m[3];
			else
				host = "localhost";

			if (m[4].matched)
				port = boost::lexical_cast<uint16>(m[4]);
		}
		else
		{
			string::size_type cp = host.find(':');
			if (cp != string::npos)
			{
				port = boost::lexical_cast<uint16>(host.substr(cp + 1));
				host.erase(cp, string::npos);
			}
		}

		// drop the username and password... is that OK?
		request.uri = m[5];
		
//		proxy_channel* channel = get_proxy_channel(host, port);
//		channel->process_request(request, reply, conn);
		shared_ptr<proxy_channel> channel(new proxy_channel(m_connection, host, port, shared_from_this()));
		channel->open([conn, channel](const boost::system::error_code& ec)
		{
			if (ec)
				conn->reply_with_error(/* ec */zh::service_unavailable, "");
			else
				channel->process_request(conn);
		});
		
		m_channels.push_back(channel);
		
//		// work around buggy IE... also, using req.accept() doesn't work since it contains */* ... duh
//		if (ba::starts_with(rep.get_content_type(), "application/xhtml+xml") and
//			not ba::contains(accept, "application/xhtml+xml") and
//			ba::contains(userAgent, "MSIE"))
//		{
//			rep.set_content_type("text/html; charset=utf-8");
//		}
	}
	catch (exception& e)
	{
		*m_log << "ERROR: " << e.what() << endl;
		conn->reply_with_error(zh::internal_server_error, e.what());
	}
}

void server::log_request(const string& client,
	const zh::request& request, const zh::reply& reply,
	const boost::posix_time::ptime& start)
{
	try
	{
		if (m_log_flags & e_log_request)
		{
			string referer = request.get_header("Referer");
			if (referer.empty()) referer = "-";
		
			string userAgent = request.get_header("User-Agent");
			if (userAgent.empty()) userAgent = "-";
		
			using namespace boost::local_time;
			local_date_time start_local(start, time_zone_ptr());
	
			*m_log << client << ' '
				 << "-" << ' '
				 << "-" << ' '
				 << start_local << ' '
				 << '"' << request.method << ' ' << request.uri << ' '
						<< "HTTP/" << request.http_version_major << '.' << request.http_version_minor << "\" "
				 << reply.get_status() << ' '
				 << reply.get_size() << ' '
				 << '"' << referer << '"' << ' '
				 << '"' << userAgent << '"'
				 << endl;
		}

		if (m_log_flags & e_log_debug)
		{
			request.debug(*m_log);
		
			*m_log << endl;
		
			reply.debug(*m_log);

			*m_log << endl;
		}
	}
	catch (...) {}
}

}

}
