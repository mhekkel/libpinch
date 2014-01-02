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

		if (m_request.http_version_minor == 1)
		{
			m_remote_address = m_request.get_header("Host");
			if (m_remote_address.empty())
				break;

			string::size_type cp = m_remote_address.find(':');
			if (cp != string::npos)
			{
				m_remote_port = boost::lexical_cast<uint16>(m_remote_address.substr(cp + 1));
				m_remote_address.erase(cp, string::npos);
			}
			else
				m_remote_port = 80;
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
			string host = m[3];
			string port = m[4];
			string file = m[5];

			if (port.empty())
				port = (scheme == "http") ? "80" : "443";

			m_remote_address = host;
			m_remote_port = boost::lexical_cast<uint16>(port);
		}

		// we now have the remote host/port, connect!
		open();
		ok = true;

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
	vector<boost::asio::const_buffer> buffers;

	// remove keep alive
	m_request.headers.erase(remove_if(m_request.headers.begin(), m_request.headers.end(), [](const zh::header& h) -> bool { return h.name == "Connection"; }), m_request.headers.end());
	m_request.http_version_minor = 0;
	
	m_request.to_buffers(buffers);

	shared_ptr<boost::asio::mutable_buffer> b(new boost::asio::mutable_buffer(new char[buffer_size(buffers)], buffer_size(buffers)));
	boost::asio::buffer_copy(*b, buffers);

	boost::asio::async_write(*this, boost::asio::buffer(*b), [this, b](const boost::system::error_code& ec, size_t)
	{
		this->handle_write_server(ec);
	});

	basic_forwarding_channel::opened();

	// start reading data channel
	boost::asio::async_read(get_socket(), m_response, boost::asio::transfer_at_least(1),
		boost::bind(&basic_forwarding_channel::receive_raw, this, boost::asio::placeholders::error));
}

void http_proxy_channel::handle_write_server(const boost::system::error_code& ec)
{
	if (ec)
	{
		m_reply = zh::reply::stock_reply(zh::internal_server_error);
		reply_error();
	}
	else if (not ec)
	{
		//vector<boost::asio::const_buffer> buffers;
		//
		//if (m_reply.data_to_buffers(buffers))
		//{
		//	boost::asio::async_write(m_socket, buffers,
		//		boost::bind(&http_proxy_channel::handle_write_server, this,
		//			boost::asio::placeholders::error));
		//}
		//else if (m_request.http_version_minor >= 1 and not m_request.close)
		//{
		//	m_request_parser.reset();
		//	m_request = zh::request();
		//	m_reply = zh::reply();

		//	m_socket.async_read_some(boost::asio::buffer(m_buffer),
		//		boost::bind(&http_proxy_channel::handle_read_client, this,
		//			boost::asio::placeholders::error,
		//			boost::asio::placeholders::bytes_transferred));
		//}
	}
}

void http_proxy_channel::reply_error()
{
	shared_ptr<vector<boost::asio::const_buffer>> buffers(new vector<boost::asio::const_buffer>());
	m_reply.to_buffers(*buffers);

	boost::asio::async_write(m_socket, *buffers,
		[this,buffers](const boost::system::error_code& ec, size_t)
		{
			close();
		});
}

}