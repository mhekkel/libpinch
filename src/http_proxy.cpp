//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <assh/config.hpp>

#include <boost/bind.hpp>
#include <boost/foreach.hpp>
#define foreach BOOST_FOREACH
#include <boost/lexical_cast.hpp>
#include <boost/regex.hpp>
#include <boost/array.hpp>
#include <boost/algorithm/string.hpp>

#include <assh/http_proxy.hpp>
#include <assh/connection.hpp>

#include <zeep/http/server.hpp>

using namespace std;
namespace ip = boost::asio::ip;
namespace zh = zeep::http;
namespace ba = boost::algorithm;

namespace assh
{

http_proxy_channel::http_proxy_channel(basic_connection& inConnection)
	: basic_forwarding_channel(inConnection)
{
}

void http_proxy_channel::start()
{
	m_request = zh::request();	// reset
	
	m_request.local_address =
		boost::lexical_cast<string>(m_socket.local_endpoint().address());
	m_request.local_port = m_socket.local_endpoint().port();
	
	m_socket.async_read_some(boost::asio::buffer(m_buffer),
		boost::bind(&http_proxy_channel::handle_read_client, this,
			boost::asio::placeholders::error,
			boost::asio::placeholders::bytes_transferred));
}

void http_proxy_channel::closed()
{
	m_socket.close();
	basic_forwarding_channel::closed();
}

void http_proxy_channel::handle_read_client(
	const boost::system::error_code& ec, size_t bytes_transferred)
{
	if (not ec)
	{
		boost::tribool result = m_request_parser.parse(
			m_request, m_buffer.data(), bytes_transferred);
		
		if (result and m_request.http_version_major == 1)
		{
			m_reply.set_version(m_request.http_version_major, m_request.http_version_minor);
			handle_request();
		}
		else if (not result)
		{
			m_reply = zh::reply::stock_reply(zh::bad_request);
			reply_error();
		}
		else
		{
			m_socket.async_read_some(boost::asio::buffer(m_buffer),
				boost::bind(&http_proxy_channel::handle_read_client, this,
					boost::asio::placeholders::error,
					boost::asio::placeholders::bytes_transferred));
		}
	}
}

void http_proxy_channel::handle_request()
{
	bool ok = false;

	for (;;)
	{
		if (m_request.method != "OPTIONS" and m_request.method != "HEAD" and m_request.method != "POST" and
			m_request.method != "GET" and m_request.method != "PUT" and m_request.method != "DELETE" and
			m_request.method != "TRACE")
			break;

		string host, port;

		if (m_request.http_version_minor == 1)
		{
			host = m_request.get_header("Host");
			if (host.empty())
				break;

			string::size_type cp = host.find(':');
			if (cp != string::npos)
			{
				port = host.substr(cp + 1);
				host.erase(cp, string::npos);
			}
			else
				port = "80";
		}
		else
		{
			boost::regex re("^([-+a-zA-Z]+)://(.+)");
			boost::smatch m;
			if (not boost::regex_match(m_request.uri, m, re))
				break;

			string scheme = ba::to_lower_copy(m[1].str());
			if (scheme != "http" and scheme != "https")
				break;

			string path = m[2];
			path = zh::decode_url(path);
		
			boost::regex re2("^(?:([-$_.+!*'(),[:alnum:];?&=]+)(?::([-$_.+!*'(),[:alnum:];?&=]+))?@)?([-[:alnum:].]+)(?::(\\d+))?/(.+)");

			if (not boost::regex_match(path, m, re2))
				break;

			string username = m[1];
			string password = m[2];
			host = m[3];
			port = m[4];
			string file = m[5];

			if (port.empty())
				port = (scheme == "http") ? "80" : "443";
		}

		ok = true;

		// we now have the remote host/port, connect if needed, else reuse the channel if it is for the same host
		if (is_open())
		{
			if (host != m_remote_address or boost::lexical_cast<uint16>(port) != m_remote_port)
			{
				m_reply = zh::reply::stock_reply(zh::service_unavailable);
				reply_error();
			}
			else
				forward_request();
		}
		else
		{
			m_remote_address = host;
			m_remote_port = boost::lexical_cast<uint16>(port);

			open();
		}

		break;
	}

	if (not ok)
	{
		m_reply = zh::reply::stock_reply(zh::bad_request);
		reply_error();
	}
}

void http_proxy_channel::opened()
{
	basic_forwarding_channel::opened();

	// start reading data channel
	boost::asio::async_read(get_socket(), m_response, boost::asio::transfer_at_least(1),
		boost::bind(&basic_forwarding_channel::receive_raw, this, boost::asio::placeholders::error));

	forward_request();
}

void http_proxy_channel::forward_request()
{
	boost::asio::streambuf* buffer = new boost::asio::streambuf;

	iostream out(buffer);
	out << m_request;

	boost::asio::async_write(*this, *buffer, [this, buffer](const boost::system::error_code& ec, size_t s)
	{
		delete buffer;
		this->handle_write_server(ec);
	});
}

void http_proxy_channel::handle_write_server(const boost::system::error_code& ec)
{
	if (ec)
	{
		m_reply = zh::reply::stock_reply(zh::internal_server_error);
		reply_error();
	}
	else
	{
//		if (m_request.http_version_minor >= 1 and not m_request.close)
//		{
//			m_request_parser.reset();
//			m_request = zh::request();
//			m_reply = zh::reply();
//
//			m_socket.async_read_some(boost::asio::buffer(m_buffer),
//				boost::bind(&http_proxy_channel::handle_read_client, this,
//					boost::asio::placeholders::error,
//					boost::asio::placeholders::bytes_transferred));
//		}

		// mimic a HTTP/1.0 server
		opacket out(msg_channel_eof);
		out	<< m_host_channel_id;
		send_data(out);
	}
}

void http_proxy_channel::reply_error()
{
	shared_ptr<vector<boost::asio::const_buffer>> buffers(new vector<boost::asio::const_buffer>());
	m_reply.to_buffers(*buffers);

	boost::asio::async_write(m_socket, *buffers,
		[this,buffers](const boost::system::error_code& ec, size_t)
		{
			if (not ec and is_open())
			{
				opacket out(msg_channel_eof);
				out	<< m_host_channel_id;
				send_data(out);
			}
			//close();
		});
}

}
