//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <pinch/pinch.hpp>

#include <regex>

#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string/regex.hpp>

#include <pinch/proxy_cmd.hpp>
#include <pinch/channel.hpp>

using namespace std;
namespace ba = boost::algorithm;

namespace pinch
{

// --------------------------------------------------------------------

class proxy_channel : public channel
{
  public:
					proxy_channel(std::shared_ptr<basic_connection> connection, const string& nc_cmd, const string& user, const string& host, int16_t port)
						: channel(connection), m_cmd(nc_cmd)
					{
						ba::replace_regex(m_cmd, std::regex("(?<!%)%r"), user);
						ba::replace_regex(m_cmd, std::regex("(?<!%)%h"), host);
						ba::replace_regex(m_cmd, std::regex("(?<!%)%p"), boost::lexical_cast<string>(port));
					}
		
	virtual void	opened()
					{
						channel::opened();
						send_request_and_command("exec", m_cmd);
					}

	string			m_cmd;
};

// --------------------------------------------------------------------

proxied_connection::proxied_connection(basic_connection* proxy, const string& nc_cmd, const string& user, const string& host, int16_t port)
	: basic_connection(proxy->get_io_service(), user)
	, m_proxy(proxy), m_channel(new proxy_channel(m_proxy, nc_cmd, user, host, port)), m_host(host)
{
	m_proxy->reference();
}

proxied_connection::~proxied_connection()
{
	if (m_channel and m_channel->is_open())
		m_channel->close();
	
	m_proxy->release();
}

void proxied_connection::set_validate_callback(const validate_callback_type& cb)
{
	m_proxy->set_validate_callback(cb);
	basic_connection::set_validate_callback(cb);
}

void proxied_connection::start_handshake()
{
	if (not m_proxy->is_connected())
	{
		m_proxy->async_connect([this](const boost::system::error_code& ec)
		{
			if (ec)
				handle_connect_result(ec);
			else
				start_handshake();
		}, channel_ptr());
	}
	else if (not m_channel->is_open())
	{
		m_channel->async_open([this](const boost::system::error_code& ec)
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

bool proxied_connection::validate_host_key(const std::string& pk_alg, const blob& host_key)
{
	return m_validate_host_key_cb and m_validate_host_key_cb(m_host, pk_alg, host_key);
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

void proxied_connection::async_read(uint32_t at_least)
{
	boost::asio::async_read(*m_channel, m_response, boost::asio::transfer_at_least(at_least),
		[this](const boost::system::error_code& ec, size_t bytes_transferred)
		{
			this->received_data(ec);
		});
}

}
