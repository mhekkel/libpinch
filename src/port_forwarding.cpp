//        Copyright Maarten L. Hekkelman 2013-2021
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)


#include "pinch/connection.hpp"
#include "pinch/port_forwarding.hpp"

namespace ip = asio_ns::ip;

namespace pinch
{

forwarding_channel::forwarding_channel(std::shared_ptr<basic_connection> inConnection,
	uint16_t local_port, const std::string &remote_addr, uint16_t remote_port)
	: channel(inConnection)
	, m_remote_address(remote_addr)
	, m_remote_port(remote_port)
	, m_local_port(local_port)
{
}

void forwarding_channel::fill_open_opacket(opacket &out)
{
	channel::fill_open_opacket(out);

	out << m_remote_address << uint32_t(m_remote_port) << "127.0.0.1" << uint32_t(m_local_port);
}

// --------------------------------------------------------------------

class forwarding_connection : public std::enable_shared_from_this<forwarding_connection>
{
  public:
	forwarding_connection(std::shared_ptr<basic_connection> ssh_connection)
		: m_socket(ssh_connection->get_executor())
	{
	}

	virtual ~forwarding_connection() = default;

	virtual void start() = 0;

	asio_ns::ip::tcp::socket &get_socket() { return m_socket; }

	void start_copy_data();

  protected:
	template <typename SocketIn, typename SocketOut>
	asio_ns::awaitable<void> copy(SocketIn &in, SocketOut &out, std::shared_ptr<forwarding_connection> self)
	{
		char data[1024];

		try
		{
			for (;;)
			{
				auto length = co_await asio_ns::async_read(in, asio_ns::buffer(data), asio_ns::transfer_at_least(1), asio_ns::use_awaitable);
				if (length == 0)
					break;
				co_await asio_ns::async_write(out, asio_ns::buffer(data, length), asio_ns::use_awaitable);
			}
		}
		catch (...) {}
	};

	std::shared_ptr<forwarding_channel> m_channel;
	asio_ns::ip::tcp::socket m_socket;
	char m_c2s_buffer[512], m_s2c_buffer[512];
	bool m_alive;
};

void forwarding_connection::start_copy_data()
{
	auto self = shared_from_this();
	asio_ns::co_spawn(m_socket.get_executor(), copy(m_socket, *m_channel, shared_from_this()), asio_ns::detached);
	asio_ns::co_spawn(m_socket.get_executor(), copy(*m_channel, m_socket, shared_from_this()), asio_ns::detached);
}

// --------------------------------------------------------------------

using forwarding_connection_factory = std::function<std::shared_ptr<forwarding_connection>()>;

class bound_port : public std::enable_shared_from_this<bound_port>
{
  public:
	virtual ~bound_port() = default;

	bound_port(std::shared_ptr<basic_connection> connection, port_forward_listener &listener, forwarding_connection_factory &&connection_factory);

	void listen(uint16_t local_port);

	uint16_t local_port() const { return m_local_port; }

  private:
	virtual void handle_accept(const asio_system_ns::error_code &ec = {});

	std::shared_ptr<basic_connection> m_connection;
	ip::tcp::acceptor m_acceptor;
	std::shared_ptr<forwarding_connection> m_new_connection;
	forwarding_connection_factory m_connection_factory;
	uint16_t m_local_port = 0;
};

bound_port::bound_port(std::shared_ptr<basic_connection> connection, port_forward_listener &listener, forwarding_connection_factory &&connection_factory)
	: m_connection(connection)
	, m_acceptor(connection->get_executor())
	, m_connection_factory(std::move(connection_factory))
{
}

void bound_port::listen(uint16_t local_port)
{
	m_local_port = local_port;

	if (m_acceptor.is_open())
		m_acceptor.close();

	m_new_connection = m_connection_factory();

	auto endpoint = asio_ns::ip::tcp::endpoint(asio_ns::ip::tcp::v4(), local_port);
	m_acceptor = asio_ns::ip::tcp::acceptor(m_connection->get_executor(), endpoint);
	m_acceptor.set_option(asio_ns::ip::tcp::acceptor::reuse_address(true));

	handle_accept();
}

void bound_port::handle_accept(const asio_system_ns::error_code &ec)
{
	if (not ec)
	{
		using namespace std::placeholders;

		m_new_connection->start();
		m_new_connection = m_connection_factory();
		m_acceptor.async_accept(m_new_connection->get_socket(),
			std::bind(&bound_port::handle_accept, shared_from_this(), _1));
	}
}

// --------------------------------------------------------------------

class port_forwarding_connection : public forwarding_connection
{
  public:
	port_forwarding_connection(std::shared_ptr<basic_connection> ssh_connection, const std::string &remote_addr, uint16_t remote_port)
		: forwarding_connection(ssh_connection)
	{
		m_channel.reset(new forwarding_channel(ssh_connection, remote_addr, remote_port));
	}

	virtual void start()
	{
		std::shared_ptr<forwarding_connection> self(shared_from_this());
		m_channel->async_open([self](const asio_system_ns::error_code &ec)
			{
			if (not ec)
				self->start_copy_data(); });
	}
};

// --------------------------------------------------------------------

class socks5_forwarding_connection : public forwarding_connection
{
  public:
	socks5_forwarding_connection(std::shared_ptr<basic_connection> inConnection)
		: forwarding_connection(inConnection)
		, m_connection(inConnection)
	{
	}

	virtual void start();

	void write_error(uint8_t error_code);
	void wrote_error();

	void handshake(const asio_system_ns::error_code &ec, size_t bytes_transferred);
	void channel_open(const asio_system_ns::error_code &ec, const std::string &remote_address, uint16_t remote_port, bool socks4);

	std::shared_ptr<socks5_forwarding_connection> self() { return std::dynamic_pointer_cast<socks5_forwarding_connection>(shared_from_this()); }

  private:
	std::shared_ptr<basic_connection> m_connection;
	blob m_buffer;
	uint8_t m_mini_buffer[1];

	enum
	{
		SOCKS_INIT,
		SOCKS4_INIT,
		SOCKS4_CONNECTION_REQUEST_USER_ID,
		SOCKS4a_CONNECTION_REQUEST_USER_ID,
		SOCKS4a_CONNECTION_REQUEST_FQDN,
		SOCKS5_INIT,
		SOCKS5_SERVERS_CHOICE,
		SOCKS5_CONNECTION_REQUEST,
		SOCKS5_CONNECTION_REQUEST_IPV4,
		SOCKS5_CONNECTION_REQUEST_IPV6,
		SOCKS5_CONNECTION_REQUEST_FQDN,
		SOCKS5_CONNECTION_REQUEST_FQDN_2,
	} m_state;
};

void socks5_forwarding_connection::start()
{
	using namespace std::placeholders;

	m_buffer.resize(2);
	m_state = SOCKS_INIT;
	asio_ns::async_read(m_socket, asio_ns::buffer(m_buffer),
		std::bind(&socks5_forwarding_connection::handshake, self(), _1, _2));
}

void socks5_forwarding_connection::handshake(const asio_system_ns::error_code &ec, size_t bytes_transferred)
{
	using namespace std::placeholders;

	auto cb = std::bind(&socks5_forwarding_connection::handshake, self(), _1, _2);

	switch (m_state)
	{
		case SOCKS_INIT:
			// SOCKS4
			if (m_buffer[0] == '\x04')
			{
				if (m_buffer[1] == 1) // only allow outbound connections
				{
					m_buffer.resize(6);
					m_state = SOCKS4_INIT;
					asio_ns::async_read(m_socket, asio_ns::buffer(m_buffer), cb);
				}
			}
			else if (m_buffer[0] == '\x05')
			{
				if (m_buffer[1] > 0)
				{
					m_buffer.resize(1);
					m_state = SOCKS5_INIT;
					asio_ns::async_read(m_socket, asio_ns::buffer(m_buffer), cb);
				}
			}
			break;

		case SOCKS4_INIT:
		{
			if (m_buffer[2] == 0 and m_buffer[3] == 0 and m_buffer[4] == 0 and m_buffer[5] != 0) // SOCKS4a
			{
				m_buffer.resize(2);
				m_state = SOCKS4a_CONNECTION_REQUEST_USER_ID;
				asio_ns::async_read(m_socket, asio_ns::buffer(m_mini_buffer), cb);
			}
			else
			{
				m_state = SOCKS4_CONNECTION_REQUEST_USER_ID;
				asio_ns::async_read(m_socket, asio_ns::buffer(m_mini_buffer), cb);
			}
			break;
		}

		case SOCKS4_CONNECTION_REQUEST_USER_ID:
			if (m_mini_buffer[0] == 0)
			{
				uint8_t *p = m_buffer.data();

				std::string remote_address;
				uint16_t remote_port;

				remote_port = *p++;
				remote_port = (remote_port << 8) | *p++;

				asio_ns::ip::address_v4::bytes_type addr;
				std::copy(p, p + 4, addr.begin());
				remote_address = asio_ns::ip::address_v4(addr).to_string();

				m_channel.reset(new forwarding_channel(m_connection, remote_address, remote_port));
				m_channel->async_open(std::bind(&socks5_forwarding_connection::channel_open, self(),
					_1, remote_address, remote_port, true));
			}
			else
				asio_ns::async_read(m_socket, asio_ns::buffer(m_mini_buffer), cb);
			break;

		case SOCKS4a_CONNECTION_REQUEST_USER_ID:
			if (m_mini_buffer[0] == 0)
				m_state = SOCKS4a_CONNECTION_REQUEST_FQDN;
			asio_ns::async_read(m_socket, asio_ns::buffer(m_mini_buffer), cb);
			break;

		case SOCKS4a_CONNECTION_REQUEST_FQDN:
		{
			if (m_mini_buffer[0] == 0)
			{
				uint8_t *p = m_buffer.data();

				std::string remote_address(m_buffer.begin() + 2, m_buffer.end());
				uint16_t remote_port;

				remote_port = *p++;
				remote_port = (remote_port << 8) | *p++;

				m_channel.reset(new forwarding_channel(m_connection, remote_address, remote_port));

				auto self = shared_from_this();
				m_channel->async_open([self, this, remote_address, remote_port](asio_system_ns::error_code ec)
					{ channel_open(ec, remote_address, remote_port, true); });
			}
			else
			{
				m_buffer.push_back(m_mini_buffer[0]);
				asio_ns::async_read(m_socket, asio_ns::buffer(m_mini_buffer), cb);
			}
			break;
		}

		case SOCKS5_INIT:
			if (find(m_buffer.begin(), m_buffer.end(), '\x00') != m_buffer.end())
			{
				m_buffer = {'\x05', '\x00'};
				m_state = SOCKS5_SERVERS_CHOICE;
				asio_ns::async_write(m_socket, asio_ns::buffer(m_buffer), cb);
			}
			break;

		case SOCKS5_SERVERS_CHOICE:
			m_state = SOCKS5_CONNECTION_REQUEST;
			m_buffer.resize(4);
			asio_ns::async_read(m_socket, asio_ns::buffer(m_buffer), cb);
			break;

		case SOCKS5_CONNECTION_REQUEST:
			if (m_buffer[0] == '\x05' and m_buffer[1] == '\x01' and
				(m_buffer[3] == '\x01' or m_buffer[3] == '\x03' or m_buffer[3] == '\x04'))
			{
				uint8_t atyp = m_buffer[3];
				switch (atyp)
				{
					case '\x01':
						m_state = SOCKS5_CONNECTION_REQUEST_IPV4;
						m_buffer.resize(4 + 2);
						break;

					case '\x04':
						m_state = SOCKS5_CONNECTION_REQUEST_IPV6;
						m_buffer.resize(16 + 2);
						break;

					default:
						m_state = SOCKS5_CONNECTION_REQUEST_FQDN;
						m_buffer.resize(1);
						break;
				}

				asio_ns::async_read(m_socket, asio_ns::buffer(m_buffer), cb);
			}
			break;

		case SOCKS5_CONNECTION_REQUEST_FQDN:
			m_buffer.resize(m_buffer[0] + 2);
			m_state = SOCKS5_CONNECTION_REQUEST_FQDN_2;
			asio_ns::async_read(m_socket, asio_ns::buffer(m_buffer), cb);
			break;

		case SOCKS5_CONNECTION_REQUEST_IPV4:
		case SOCKS5_CONNECTION_REQUEST_IPV6:
		case SOCKS5_CONNECTION_REQUEST_FQDN_2:
		{
			uint8_t *p = m_buffer.data();

			std::string remote_address;
			uint16_t remote_port;

			switch (m_state)
			{
				case SOCKS5_CONNECTION_REQUEST_IPV4:
				{
					asio_ns::ip::address_v4::bytes_type addr;
					std::copy(p, p + 4, addr.begin());
					remote_address = asio_ns::ip::address_v4(addr).to_string();
					p += 4;
					break;
				}

				case SOCKS5_CONNECTION_REQUEST_IPV6:
				{
					asio_ns::ip::address_v6::bytes_type addr;
					std::copy(p, p + 16, addr.begin());
					remote_address = asio_ns::ip::address_v6(addr).to_string();
					p += 16;
					break;
				}

				default:
				{
					remote_address.assign(p, p + m_buffer.size() - 2);
					p += m_buffer.size() - 2;
					break;
				}
			}

			remote_port = *p++;
			remote_port = (remote_port << 8) | *p;

			m_channel.reset(new forwarding_channel(m_connection, remote_address, remote_port));
			auto self = shared_from_this();
			m_channel->async_open([self, this, remote_address, remote_port](asio_system_ns::error_code ec)
				{ channel_open(ec, remote_address, remote_port, false); });
			break;
		}
	}
}

void socks5_forwarding_connection::channel_open(const asio_system_ns::error_code &ec, const std::string &remote_address, uint16_t remote_port, bool socks4)
{
	if (not ec)
	{
		if (socks4)
		{
			m_buffer = {0, 0x5a, static_cast<uint8_t>(remote_port >> 8), static_cast<uint8_t>(remote_port), 127, 0, 0, 1};
		}
		else
		{
			m_buffer.resize(4 + 2 + remote_address.length() + 1);
			m_buffer[0] = '\x05';
			m_buffer[1] = '\x00';
			m_buffer[2] = 0;
			m_buffer[3] = '\x03';
			m_buffer[4] = static_cast<uint8_t>(remote_address.length());
			std::copy(remote_address.begin(), remote_address.end(), m_buffer.begin() + 5);
			m_buffer[m_buffer.size() - 2] = static_cast<uint8_t>(remote_port >> 8);
			m_buffer[m_buffer.size() - 1] = static_cast<uint8_t>(remote_port);
		}

		asio_ns::async_write(m_socket, asio_ns::buffer(m_buffer),
			[](const asio_system_ns::error_code &ec, size_t bytes_transferred) {});

		start_copy_data();
	}
}

void socks5_forwarding_connection::wrote_error()
{
}

// --------------------------------------------------------------------

port_forward_listener::port_forward_listener(std::shared_ptr<basic_connection> connection)
	: m_connection(connection)
{
}

port_forward_listener::~port_forward_listener()
{
}

void port_forward_listener::forward_port(uint16_t local_port, const std::string &remote_address, uint16_t remote_port)
{
	for (auto p : m_bound_ports)
	{
		if (p->local_port() == local_port)
		{
			p->listen(local_port);
			return;
		}
	}

	std::shared_ptr<bound_port> p(new bound_port(m_connection, *this,
		[this, remote_address, remote_port]()
		{
			return std::shared_ptr<forwarding_connection>(new port_forwarding_connection(m_connection, remote_address, remote_port));
		}));

	p->listen(local_port);
	m_bound_ports.push_back(p);
}

void port_forward_listener::forward_socks5(uint16_t local_port)
{
	for (auto p : m_bound_ports)
	{
		if (p->local_port() == local_port)
		{
			p->listen(local_port);
			return;
		}
	}

	std::shared_ptr<bound_port> p(new bound_port(m_connection, *this,
		[this]()
		{
			return std::shared_ptr<forwarding_connection>(new socks5_forwarding_connection(m_connection));
		}));

	p->listen(local_port);
	m_bound_ports.push_back(p);
}

// void port_forward_listener::accept_failed(const asio_system_ns::error_code& ec, bound_port* e)
//{
//	//m_bound_ports.erase(remove(m_bound_ports.begin(), m_bound_ports.end(), e), m_bound_ports.end());
//	//delete e;
// }

void port_forward_listener::connection_closed()
{
	m_bound_ports.clear();
}

} // namespace pinch
