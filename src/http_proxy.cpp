//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <assh/config.hpp>

#include <fstream>

#include <../Lib/MResources.h>

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
#include <boost/asio/spawn.hpp>

#include <assh/http_proxy.hpp>
#include <assh/connection.hpp>

#include <zeep/http/server.hpp>
#include <zeep/http/message_parser.hpp>

#if defined(_MSC_VER)

#define BOOST_LIB_NAME boost_coroutine

// tell the auto-link code to select a dll when required:
#if defined(BOOST_ALL_DYN_LINK) || defined(BOOST_WAVE_DYN_LINK)
#define BOOST_DYN_LINK
#endif

#include <boost/config/auto_link.hpp>

#endif

using namespace std;
namespace ip = boost::asio::ip;
namespace zh = zeep::http;
namespace ba = boost::algorithm;

namespace assh {
namespace http_proxy {

using namespace boost::posix_time;

class proxy_connection;

// --------------------------------------------------------------------

class proxy_connection : public std::tr1::enable_shared_from_this<proxy_connection>
{
  public:
	proxy_connection(basic_connection& ssh_connection, shared_ptr<server> proxy)
		: m_ssh_connection(ssh_connection), m_proxy(proxy), m_socket(m_ssh_connection.get_io_service())
		, m_strand(m_ssh_connection.get_io_service()) {}

	void start();
	void reply_with_error(zh::status_type err, const string& message);
	void reply();
	void connect(shared_ptr<channel> channel);
	
	boost::asio::ip::tcp::socket& get_socket() { return m_socket; }
	boost::asio::io_service::strand& get_strand() { return m_strand; }
	
	zh::reply& get_reply() { return m_reply; }
	zh::request& get_request() { return m_request; }

  private:

	void handle_read(const boost::system::error_code& ec, size_t bytes_transferred);
	void handle_write(const boost::system::error_code& ec);

	void connect_copy_c2s(boost::asio::yield_context yield, shared_ptr<channel> channel);
	void connect_copy_s2c(boost::asio::yield_context yield, shared_ptr<channel> channel);
	
	basic_connection& m_ssh_connection;
	shared_ptr<server> m_proxy;
	boost::asio::ip::tcp::socket m_socket;
	zh::request_parser m_request_parser;
	boost::array<char,8192> m_buffer;
	zh::request m_request;
	zh::reply m_reply;
	bool m_keep_alive;
	ptime m_start;
	
	shared_ptr<channel> m_connect_channel;
	boost::asio::io_service::strand m_strand;
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

void proxy_connection::connect(shared_ptr<channel> channel)
{
	m_reply = zh::reply::stock_reply(zh::ok);

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
	
	shared_ptr<proxy_connection> self(shared_from_this());

	boost::asio::async_write(m_socket, buffers, [this, self, channel](const boost::system::error_code& ec, size_t bytes_transferred)
	{
		if (ec)
			self->m_proxy->log_error(ec);
		else
		{
			boost::asio::spawn(self->m_strand, boost::bind(&proxy_connection::connect_copy_s2c, self, _1, channel));
			boost::asio::spawn(self->m_strand, boost::bind(&proxy_connection::connect_copy_c2s, self, _1, channel));
		}
	});
}

void proxy_connection::connect_copy_c2s(boost::asio::yield_context yield, shared_ptr<channel> channel)
{
	try
	{
		char data[1024];

		for (;;)
		{
			size_t length = m_socket.async_read_some(boost::asio::buffer(data), yield);
			boost::asio::async_write(*channel, boost::asio::buffer(data, length), yield);
		}
	}
	catch (exception& e)
	{
		m_proxy->log_error(e);
		channel->close();
	}
}

void proxy_connection::connect_copy_s2c(boost::asio::yield_context yield, shared_ptr<channel> channel)
{
	try
	{
		char data[1024];

		for (;;)
		{
			size_t length = boost::asio::async_read(*channel, boost::asio::buffer(data), boost::asio::transfer_at_least(1), yield);
			boost::asio::async_write(m_socket, boost::asio::buffer(data, length), yield);
		}
	}
	catch (exception& e)
	{
		m_proxy->log_error(e);
		channel->close();
	}
}

// --------------------------------------------------------------------

class proxy_channel : public channel
{
  public:
	proxy_channel(basic_connection& inConnection,
		const std::string& remote_addr, uint16 remote_port,
		shared_ptr<server> proxy)
		: channel(inConnection), m_proxy(proxy)
		, m_remote_address(remote_addr), m_remote_port(remote_port) {}

	virtual void closed();

	virtual string channel_type() const				{ return "direct-tcpip"; }
	virtual void fill_open_opacket(opacket& out)
	{
		channel::fill_open_opacket(out);
	
		//boost::asio::ip::address originator = get_socket().remote_endpoint().address();
		//string originator_address = boost::lexical_cast<string>(originator);
		//uint16 originator_port = get_socket().remote_endpoint().port();
		string originator_address = "127.0.0.1";
		uint16 originator_port = 80;
	
		out << m_remote_address << uint32(m_remote_port) << originator_address << uint32(originator_port);
	}

	void process_request(shared_ptr<proxy_connection> proxy_connection);

  private:
	
	void proxy_channel::process_request(boost::asio::yield_context yield, channel_ptr, shared_ptr<boost::asio::streambuf>,
		shared_ptr<proxy_connection> proxy_connection);

	string m_remote_address;
	uint16 m_remote_port;
	shared_ptr<server> m_proxy;
};

// --------------------------------------------------------------------

void proxy_channel::closed()
{
	channel::closed();
	m_proxy->channel_closed(this);
}

void proxy_channel::process_request(shared_ptr<proxy_connection> proxy_connection)
{
	shared_ptr<boost::asio::streambuf> buffer(new boost::asio::streambuf);

	iostream out(buffer.get());
	out << proxy_connection->get_request();

	boost::asio::spawn(proxy_connection->get_strand(),
		boost::bind(&proxy_channel::process_request, this, _1, shared_from_this(), buffer, proxy_connection));
}

void proxy_channel::process_request(boost::asio::yield_context yield, shared_ptr<channel> self,
	shared_ptr<boost::asio::streambuf> buffer, shared_ptr<proxy_connection> proxy_connection)
{
	try
	{
		boost::asio::async_write(*this, *buffer, yield);
		
		zh::reply_parser p;
		char data[1024];
		
		for (;;)
		{
			boost::system::error_code ec;
			size_t l = boost::asio::async_read(*this, boost::asio::buffer(data), boost::asio::transfer_at_least(1), yield);
			
			boost::tribool result;
			size_t consumed;
			
			tr1::tie(result, consumed) = p.parse(proxy_connection->get_reply(), data, l);
			if (result)
			{
				proxy_connection->reply();
				break;
			}
			else if (not result)
			{
				proxy_connection->reply_with_error(zh::internal_server_error, "");
				break;
			}
			else
				continue;
		}
	}
	catch (exception& e)
	{
		m_proxy->log_error(e);
	}
		
	close();
}

// --------------------------------------------------------------------

server::server(basic_connection& ssh_connection, uint32 log_flags)
	: template_processor("http://www.hekkelman.com/ns/salt"), m_connection(ssh_connection), m_log_flags(log_flags)
{
}

void server::set_log_flags(uint32 log_flags)
{
	m_log_flags = log_flags;

	if (m_log_flags)
	{
		using namespace boost::local_time;

		m_log.reset(new ofstream("proxy.log", ios::app));

		local_time_facet* lf(new local_time_facet("[%d/%b/%Y:%H:%M:%S %z]"));
		m_log->imbue(locale(cout.getloc(), lf));
	}
	else
		m_log.reset();
}

void server::load_template(const std::string& file, zeep::xml::document& doc)
{
	mrsrc::rsrc rsrc(string("templates/") + file);
	if (not rsrc)
		throw runtime_error("missing template");
	
	string data(rsrc.data(), rsrc.size());
	doc.read(data);
}

void server::listen(uint16 port)
{
	if (m_log)
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
		if (request.method == "CONNECT")
		{
			string host = request.uri;
			uint16 port = 443;

			string::size_type cp = host.find(':');
			if (cp != string::npos)
			{
				port = boost::lexical_cast<uint16>(host.substr(cp + 1));
				host.erase(cp, string::npos);
			}

			shared_ptr<proxy_channel> channel(new proxy_channel(m_connection, host, port, shared_from_this()));
			channel->open([conn, channel](const boost::system::error_code& ec)
			{
				if (ec)
					conn->reply_with_error(/* ec */zh::service_unavailable, "");
				else
					conn->connect(channel);
			});
			
			m_channels.push_back(channel);
		}
		else if (request.method == "OPTIONS" or request.method == "HEAD" or request.method == "POST" or
				 request.method == "GET" or request.method == "PUT" or request.method == "DELETE" or
				 request.method == "TRACE")
		{
			string host = request.get_header("Host");
			uint16 port = 80;

			boost::regex re("^(?:http://)?(?:([-$_.+!*'(),[:alnum:];?&=]+)(?::([-$_.+!*'(),[:alnum:];?&=]+))?@)?([-[:alnum:].]+)(?::(\\d+))?(/.*)?");
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
			
			if (host == "proxy.hekkelman.net" and port == 80)
			{
				zh::el::scope scope(request);
				create_reply_from_template("index.xhtml", scope, conn->get_reply());
				conn->reply();
			}
			else
			{
				shared_ptr<proxy_channel> channel(new proxy_channel(m_connection, host, port, shared_from_this()));
				channel->open([conn, channel](const boost::system::error_code& ec)
				{
					if (ec)
						conn->reply_with_error(/* ec */zh::service_unavailable, "");
					else
						channel->process_request(conn);
				});
			
				m_channels.push_back(channel);
			}
		}
		else
			conn->reply_with_error(zh::bad_request, "Invalid method requested");
		
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
		if (m_log)
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

void server::log_error(const std::exception& e)
{
	if (m_log)
		*m_log << "ERROR: " << e.what() << endl;
}

void server::log_error(const boost::system::error_code& ec)
{
	if (m_log)
		*m_log << "ERROR: " << ec << endl;
}

void server::channel_closed(proxy_channel* ch)
{
	m_channels.erase(remove_if(m_channels.begin(), m_channels.end(), [ch](const shared_ptr<channel>& p) -> bool
	{
		return p.get() == ch;
	}), m_channels.end());
}

}

}
