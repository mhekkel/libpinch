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

#include <assh/port_forwarding.hpp>
#include <assh/connection.hpp>
#include <assh/http_proxy.hpp>

using namespace std;
namespace ip = boost::asio::ip;

namespace assh
{

// --------------------------------------------------------------------

typedef boost::function<basic_forwarding_channel*()> channel_factory;

struct bound_port
{
	bound_port(basic_connection& connection, port_forward_listener& listener,
		const string& local_address, uint16 local_port, channel_factory&& make_channel);
	virtual ~bound_port() {}

	virtual void handle_accept(const boost::system::error_code& ec);
	
	basic_connection& m_connection;
	port_forward_listener& m_listener;
	ip::tcp::acceptor m_acceptor;
	ip::tcp::resolver m_resolver;
	unique_ptr<basic_forwarding_channel> m_new_channel;
	string m_local_address;
	uint16 m_local_port;
	channel_factory m_channel_factory;
};

bound_port::bound_port(basic_connection& connection, port_forward_listener& listener,
		const string& local_address, uint16 local_port,
		channel_factory&& make_channel)
	: m_connection(connection), m_listener(listener)
	, m_acceptor(connection.get_io_service()), m_resolver(connection.get_io_service())
	, m_local_address(local_address), m_local_port(local_port)
	, m_channel_factory(make_channel)
{
	ip::tcp::resolver::query query(m_local_address, boost::lexical_cast<string>(m_local_port));
	m_resolver.async_resolve(query, [this](const boost::system::error_code& ec, ip::tcp::resolver::iterator iterator)
	{
		if (iterator != ip::tcp::resolver::iterator())
		{
			m_new_channel.reset(m_channel_factory());

			m_acceptor.open(iterator->endpoint().protocol());
			m_acceptor.set_option(ip::tcp::acceptor::reuse_address(true));
			m_acceptor.bind(*iterator);
			m_acceptor.listen();
			m_acceptor.async_accept(m_new_channel->get_socket(),
				boost::bind(&bound_port::handle_accept, this, boost::asio::placeholders::error));
		}
		else if (ec)
			m_listener.accept_failed(ec, this);
	});
}

void bound_port::handle_accept(const boost::system::error_code& ec)
{
	if (ec)
		m_listener.accept_failed(ec, this);
	else
	{
		basic_forwarding_channel* channel = m_new_channel.release();
		channel->start();

		m_new_channel.reset(m_channel_factory());
		m_acceptor.async_accept(m_new_channel->get_socket(),
			boost::bind(&bound_port::handle_accept, this, boost::asio::placeholders::error));
	}
}

// --------------------------------------------------------------------

basic_forwarding_channel::basic_forwarding_channel(basic_connection& inConnection)
	: channel(inConnection)
	, m_socket(inConnection.get_io_service())
{
}

void basic_forwarding_channel::fill_open_opacket(opacket& out)
{
	channel::fill_open_opacket(out);

	boost::asio::ip::address originator = get_socket().remote_endpoint().address();
	string originator_address = boost::lexical_cast<string>(originator);
	uint16 originator_port = get_socket().remote_endpoint().port();

	out << m_remote_address << uint32(m_remote_port) << originator_address << uint32(originator_port);
}

void basic_forwarding_channel::closed()
{
	channel::closed();
	
	if (not get_socket().is_open())
	{
		m_connection.get_io_service().post([this]
		{
			delete this;
		});
	}
}

void basic_forwarding_channel::receive_data(const char* data, size_t size)
{
	shared_ptr<boost::asio::streambuf> buffer(new boost::asio::streambuf);
	ostream out(buffer.get());
	
	out.write(data, size);
	
	boost::asio::async_write(get_socket(), *buffer,
		[this, buffer](const boost::system::error_code& ec, size_t)
		{
			if (ec)
				close();
		});
}

void basic_forwarding_channel::receive_raw(const boost::system::error_code& ec)
{
	if (ec)
	{
		get_socket().close();
		close();
	}
	else
	{
		istream in(&m_response);
	
		for (;;)
		{
			char buffer[8192];
	
			size_t k = static_cast<size_t>(in.readsome(buffer, sizeof(buffer)));
			if (k == 0)
				break;
			
			send_data(buffer, k,
				[this](const boost::system::error_code& ec, size_t)
				{
					if (ec)
						close();
				});
		}
		
		boost::asio::async_read(get_socket(), m_response, boost::asio::transfer_at_least(1),
			boost::bind(&basic_forwarding_channel::receive_raw, this, boost::asio::placeholders::error));
	}
}

// --------------------------------------------------------------------

class port_forwarding_channel : public basic_forwarding_channel
{
  public:	

	port_forwarding_channel(basic_connection& inConnection,
		const std::string& remote_addr, uint16 remote_port)
		: basic_forwarding_channel(inConnection)
	{
		m_remote_address = remote_addr;
		m_remote_port = remote_port;
	}

	virtual void start()
	{
		open();
	}
	
	virtual void opened()
	{
		basic_forwarding_channel::opened();
		
		// start the read loop
		boost::asio::async_read(m_socket, m_response, boost::asio::transfer_at_least(1),
			boost::bind(&port_forwarding_channel::receive_raw, this,
			boost::asio::placeholders::error));
	}
};

// --------------------------------------------------------------------

class socks5_proxy_channel : public basic_forwarding_channel
{
  public:

	socks5_proxy_channel(basic_connection& inConnection)
		: basic_forwarding_channel(inConnection), m_accepted(false) {}

	virtual void opened();
	virtual void start();

	void read_handshake_1(const boost::system::error_code& ec, size_t bytes_transferred);
	void read_handshake_2(const boost::system::error_code& ec, size_t bytes_transferred);
	void wrote_handshake(const boost::system::error_code& ec, size_t bytes_transferred);
	void read_request_1(const boost::system::error_code& ec, size_t bytes_transferred);
	void read_request_addr(const boost::system::error_code& ec, size_t bytes_transferred, uint8 atyp);
	void read_request_domain_name(const boost::system::error_code& ec, size_t bytes_transferred, uint8 atyp);
	
	void write_error(uint8 error_code);
	void wrote_error();

	bool m_accepted;
	vector<uint8> m_buffer;
};

void socks5_proxy_channel::start()
{
	m_buffer.resize(2);
	boost::asio::async_read(m_socket, boost::asio::buffer(m_buffer),
		boost::bind(&socks5_proxy_channel::read_handshake_1, this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
}

void socks5_proxy_channel::read_handshake_1(const boost::system::error_code& ec, size_t bytes_transferred)
{
	if (ec)
		m_connection.get_io_service().post([this]() { delete this; });
	else if (m_buffer[0] == '\x05' and m_buffer[1] > 0)
	{
		m_buffer.resize(m_buffer[1]);
		boost::asio::async_read(m_socket, boost::asio::buffer(m_buffer),
			boost::bind(&socks5_proxy_channel::read_handshake_2, this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
	}
	else
	{
		m_buffer.resize(2);
		m_buffer[0] = '\x05';
		m_buffer[1] = '\xff';
		
		boost::asio::async_write(m_socket, boost::asio::buffer(m_buffer),
			boost::bind(&socks5_proxy_channel::wrote_error, this));
	}
}

void socks5_proxy_channel::read_handshake_2(const boost::system::error_code& ec, size_t bytes_transferred)
{
	if (ec)
		m_connection.get_io_service().post([this]() { delete this; });
	else if (find(m_buffer.begin(), m_buffer.end(), '\x00') != m_buffer.end())
	{
		m_buffer.resize(2);
		m_buffer[0] = '\x05';
		m_buffer[1] = '\x00';
		
		boost::asio::async_write(m_socket, boost::asio::buffer(m_buffer),
			boost::bind(&socks5_proxy_channel::wrote_handshake, this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
	}
	else
	{
		m_buffer.resize(2);
		m_buffer[0] = '\x05';
		m_buffer[1] = '\xff';
		
		boost::asio::async_write(m_socket, boost::asio::buffer(m_buffer),
			boost::bind(&socks5_proxy_channel::wrote_error, this));
	}
}

void socks5_proxy_channel::wrote_handshake(const boost::system::error_code& ec, size_t bytes_transferred)
{
	if (ec)
		m_connection.get_io_service().post([this]() { delete this; });
	else
	{
		m_buffer.resize(4);
		boost::asio::async_read(m_socket, boost::asio::buffer(m_buffer),
			boost::bind(&socks5_proxy_channel::read_request_1, this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
	}
}

void socks5_proxy_channel::read_request_1(const boost::system::error_code& ec, size_t bytes_transferred)
{
	if (ec or m_buffer[0] != '\x05' or m_buffer[1] != '\x01' or
			(m_buffer[3] != '\x01' and m_buffer[3] != '\x03' and m_buffer[3] != '\x04'))
	{
		m_connection.get_io_service().post([this]() { delete this; });
	}
	else
	{
		uint8 atyp = m_buffer[3];
		switch (atyp)
		{
			case '\x01':
				m_buffer.resize(4 + 2);
				break;

			case '\x04':
				m_buffer.resize(16 + 2);
				break;

			default:
				m_buffer.resize(1);
				break;
		}
		
		boost::asio::async_read(m_socket, boost::asio::buffer(m_buffer),
			boost::bind(&socks5_proxy_channel::read_request_addr, this,
				boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred, atyp));
	}
}

void socks5_proxy_channel::read_request_addr(const boost::system::error_code& ec, size_t bytes_transferred, uint8 atyp)
{
	if (ec)
		m_connection.get_io_service().post([this]() { delete this; });
	else if (m_buffer.size() == 1)
	{
		m_buffer.resize(uint32(m_buffer[0]) + 2);

		boost::asio::async_read(m_socket, boost::asio::buffer(m_buffer),
			boost::bind(&socks5_proxy_channel::read_request_domain_name, this,
				boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred, atyp));
	}
	else
	{
		uint8* p = &m_buffer[0];
		
		switch (atyp)
		{
			case '\x01':
			{
				boost::asio::ip::address_v4::bytes_type addr;
				copy(p, p + 4, addr.begin());
				m_remote_address = boost::lexical_cast<string>(boost::asio::ip::address_v4(addr));
				p += 4;
				break;
			}
	
			case '\x04':
			{
				boost::asio::ip::address_v6::bytes_type addr;
				copy(p, p + 16, addr.begin());
				m_remote_address = boost::lexical_cast<string>(boost::asio::ip::address_v6(addr));
				p += 16;
				break;
			}
		}
		
		m_remote_port = *p++;
		m_remote_port = (m_remote_port << 8) | *p;
		
		// OK, got an address, try to open it
		open();
	}
}

void socks5_proxy_channel::read_request_domain_name(const boost::system::error_code& ec, size_t bytes_transferred, uint8 atyp)
{
	if (ec)
		m_connection.get_io_service().post([this]() { delete this; });
	else
	{
		uint8* p = &m_buffer[0];
		
		m_remote_address.assign(p, p + m_buffer.size() - 2);
		p += m_buffer.size() - 2;

		m_remote_port = *p++;
		m_remote_port = (m_remote_port << 8) | *p;
		
		// OK, got an address, try to open it
		open();
	}
}

void socks5_proxy_channel::opened()
{
	basic_forwarding_channel::opened();
	
	m_accepted = true;
	
	m_buffer.resize(4 + 2 + m_remote_address.length() + 1);
	m_buffer[0] = '\x05';
	m_buffer[1] = '\x00';
	m_buffer[2] = 0;
	m_buffer[3] = '\x03';
	m_buffer[4] = static_cast<uint8>(m_remote_address.length());
	copy(m_remote_address.begin(), m_remote_address.end(), m_buffer.begin() + 5);
	m_buffer[m_buffer.size() - 2] = static_cast<uint8>(m_remote_port >> 8);
	m_buffer[m_buffer.size() - 1] = static_cast<uint8>(m_remote_port);

	boost::asio::async_write(m_socket, boost::asio::buffer(m_buffer),
		[](const boost::system::error_code& ec, size_t bytes_transferred){});
	
	// start the read loop
	boost::asio::async_read(m_socket, m_response, boost::asio::transfer_at_least(1),
		boost::bind(&port_forwarding_channel::receive_raw, this, boost::asio::placeholders::error));
}

void socks5_proxy_channel::wrote_error()
{
	m_connection.get_io_service().post([this]() { delete this; });
}

// --------------------------------------------------------------------

port_forward_listener::port_forward_listener(basic_connection& connection)
	: m_connection(connection)
{
}

port_forward_listener::~port_forward_listener()
{
	for_each(m_bound_ports.begin(), m_bound_ports.end(), [](bound_port* e) { delete e; });
}

void port_forward_listener::forward_port(const string& local_addr, uint16 local_port,
	const string& remote_address, uint16 remote_port)
{
	m_bound_ports.push_back(
		new bound_port(m_connection, *this, local_addr, local_port,
			[this, remote_address, remote_port]() -> basic_forwarding_channel*
			{
				return new port_forwarding_channel(m_connection, remote_address, remote_port);
			}));
}

void port_forward_listener::forward_http(const string& local_addr, uint16 local_port)
{
	m_http_proxy.reset(new http_proxy::server(m_connection));
	m_http_proxy->listen(local_port);
}

void port_forward_listener::forward_socks5(const string& local_addr, uint16 local_port)
{
	m_bound_ports.push_back(
		new bound_port(m_connection, *this, local_addr, local_port,
			[this]() -> basic_forwarding_channel* { return new socks5_proxy_channel(m_connection); }));
}

void port_forward_listener::accept_failed(const boost::system::error_code& ec, bound_port* e)
{
	m_bound_ports.erase(remove(m_bound_ports.begin(), m_bound_ports.end(), e), m_bound_ports.end());
	delete e;
}

void port_forward_listener::connection_closed()
{
	for_each(m_bound_ports.begin(), m_bound_ports.end(), [](bound_port* e) { delete e; });
	m_bound_ports.clear();
}

}
