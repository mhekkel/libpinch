//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <assh/config.hpp>

#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string/regex.hpp>

#include <assh/proxy_cmd.hpp>
#include <assh/channel.hpp>

using namespace std;
namespace ba = boost::algorithm;

namespace assh
{

// --------------------------------------------------------------------

class proxy_channel : public channel
{
  public:
					proxy_channel(basic_connection& connection, const string& nc_cmd, const string& user, const string& host, uint16 port)
						: channel(connection), m_cmd(nc_cmd)
					{
						ba::replace_regex(m_cmd, boost::regex("(?<!%)%r"), user);
						ba::replace_regex(m_cmd, boost::regex("(?<!%)%h"), host);
						ba::replace_regex(m_cmd, boost::regex("(?<!%)%p"), boost::lexical_cast<string>(port));
					}
		
	virtual void	setup(ipacket& in)
					{
						send_request_and_command("exec", m_cmd);
					}

	string			m_cmd;
};

// --------------------------------------------------------------------

proxied_connection::proxied_connection(basic_connection& proxy, const string& nc_cmd, const string& user, const string& host, uint16 port)
	: basic_connection(proxy.get_io_service(), user)
	, m_proxy(proxy), m_channel(new proxy_channel(m_proxy, nc_cmd, user, host, port)), m_host(host)
{
}

proxied_connection::~proxied_connection()
{
	if (m_channel)
		m_channel->close();
	delete m_channel;
}

void proxied_connection::start_handshake()
{
	if (not m_proxy.is_connected())
	{
		m_proxy.async_connect([this](const boost::system::error_code& ec)
		{
			if (ec)
				handle_connect_result(ec);
			else
				start_handshake();
		});
	}
	else if (not m_channel->is_open())
	{
		m_channel->open([this](const boost::system::error_code& ec)
		{
			if (ec)
				handle_connect_result(ec);
			else
				start_handshake();
		});
	}
	else	// proxy connection and channel are now open
		basic_connection::start_handshake();
}

bool proxied_connection::validate_host_key(const std::string& pk_alg, const std::vector<uint8>& host_key)
{
	return cb_validate_host_key and cb_validate_host_key(m_host, pk_alg, host_key);
}

void proxied_connection::async_write_int(boost::asio::streambuf* request, basic_write_op* op)
{
	boost::asio::async_write(*m_channel, *request,
		[op, request](const boost::system::error_code& ec, size_t bytes_transferred)
		{
			delete request;
			(*op)(ec, bytes_transferred);
			delete op;
		});
}

void proxied_connection::async_read_version_string()
{
	boost::asio::async_read_until(*m_channel, m_response, "\n",
		[this](const boost::system::error_code& ec, size_t bytes_transferred)
	{
		handle_protocol_version_response(ec, bytes_transferred);
	});
}

void proxied_connection::async_read(uint32 at_least)
{
	boost::asio::async_read(*m_channel, m_response, boost::asio::transfer_at_least(at_least),
		[this](const boost::system::error_code& ec, size_t bytes_transferred)
		{
			this->received_data(ec);
		});
}

}
