//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <assh/config.hpp>

#include <functional>
#include <regex>

#include <boost/lexical_cast.hpp>

#include <assh/port_forwarding.hpp>
#include <assh/connection.hpp>

using namespace std;
namespace ip = boost::asio::ip;

namespace assh
{

forwarding_channel::forwarding_channel(std::shared_ptr<connection_base> inConnection, const string& remote_addr, int16_t remote_port)
	: channel(inConnection), m_remote_address(remote_addr), m_remote_port(remote_port)
{
}

void forwarding_channel::fill_open_opacket(opacket& out)
{
	channel::fill_open_opacket(out);

	//boost::asio::ip::address originator = get_socket().remote_endpoint().address();
	//string originator_address = boost::lexical_cast<string>(originator);
	//int16_t originator_port = get_socket().remote_endpoint().port();

	string originator_address = "127.0.0.1";
	int16_t originator_port = 80;

	out << m_remote_address << uint32_t(m_remote_port) << originator_address << uint32_t(originator_port);
}

// --------------------------------------------------------------------

class forwarding_connection : public enable_shared_from_this<forwarding_connection>
{
  public:
	forwarding_connection(std::shared_ptr<connection_base> ssh_connection)
		: m_socket(ssh_connection->get_io_service())
	{
	}

	virtual ~forwarding_connection() {}

	virtual void start() = 0;

	boost::asio::ip::tcp::socket& get_socket() { return m_socket; }

	void start_copy_data();

  protected:

	void handle_read_from_client(const boost::system::error_code& ec, size_t bytes_transferred);
	void handle_wrote_to_client(const boost::system::error_code& ec, size_t bytes_transferred);
	void handle_read_from_server(const boost::system::error_code& ec, size_t bytes_transferred);
	void handle_wrote_to_server(const boost::system::error_code& ec, size_t bytes_transferred);

	shared_ptr<forwarding_channel> m_channel;
	boost::asio::ip::tcp::socket m_socket;
	char m_c2s_buffer[512], m_s2c_buffer[512];
	bool m_alive;
};

void forwarding_connection::start_copy_data()
{
	boost::asio::async_read(m_socket, boost::asio::buffer(m_c2s_buffer),
							boost::asio::transfer_at_least(1),
							boost::bind(&forwarding_connection::handle_read_from_client, shared_from_this(), boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
	boost::asio::async_read(*m_channel, boost::asio::buffer(m_s2c_buffer),
							boost::asio::transfer_at_least(1),
							boost::bind(&forwarding_connection::handle_read_from_server, shared_from_this(), boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
}

void forwarding_connection::handle_read_from_client(const boost::system::error_code& ec, size_t bytes_transferred)
{
	if (not ec)
		boost::asio::async_write(*m_channel, boost::asio::buffer(m_c2s_buffer, bytes_transferred),
								 boost::bind(&forwarding_connection::handle_wrote_to_server, shared_from_this(), boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
}

void forwarding_connection::handle_wrote_to_server(const boost::system::error_code& ec, size_t bytes_transferred)
{
	if (not ec)
		boost::asio::async_read(m_socket, boost::asio::buffer(m_c2s_buffer),
		boost::asio::transfer_at_least(1),
		boost::bind(&forwarding_connection::handle_read_from_client, shared_from_this(), boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
}

void forwarding_connection::handle_read_from_server(const boost::system::error_code& ec, size_t bytes_transferred)
{
	if (not ec)
		boost::asio::async_write(m_socket, boost::asio::buffer(m_s2c_buffer, bytes_transferred),
		boost::bind(&forwarding_connection::handle_wrote_to_client, shared_from_this(), boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
}

void forwarding_connection::handle_wrote_to_client(const boost::system::error_code& ec, size_t bytes_transferred)
{
	if (not ec)
		boost::asio::async_read(*m_channel, boost::asio::buffer(m_s2c_buffer),
		boost::asio::transfer_at_least(1),
		boost::bind(&forwarding_connection::handle_read_from_server, shared_from_this(), boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
}

// --------------------------------------------------------------------

typedef function<shared_ptr<forwarding_connection>()> forwarding_connection_factory;

class bound_port : public enable_shared_from_this<bound_port>
{
  public:
	bound_port(std::shared_ptr<connection_base> connection, port_forward_listener& listener, forwarding_connection_factory&& connection_factory);

	void listen(const string& local_address, int16_t local_port);

  private:
	virtual void handle_accept(const boost::system::error_code& ec);
	
	std::shared_ptr<connection_base> m_connection;
	ip::tcp::acceptor m_acceptor;
	ip::tcp::resolver m_resolver;
	shared_ptr<forwarding_connection> m_new_connection;
	forwarding_connection_factory m_connection_factory;
};

bound_port::bound_port(std::shared_ptr<connection_base> connection, port_forward_listener& listener, forwarding_connection_factory&& connection_factory)
	: m_connection(connection)
	, m_acceptor(connection->get_io_service()), m_resolver(connection->get_io_service())
	, m_connection_factory(move(connection_factory))
{
}

void bound_port::listen(const string& local_address, int16_t local_port)
{
	ip::tcp::resolver::query query(local_address, boost::lexical_cast<string>(local_port));

	shared_ptr<bound_port> self(shared_from_this());
	m_resolver.async_resolve(query, [self, this](const boost::system::error_code& ec, ip::tcp::resolver::iterator iterator)
	{
		if (iterator != ip::tcp::resolver::iterator())
		{
			m_new_connection = m_connection_factory();

			m_acceptor.open(iterator->endpoint().protocol());
			m_acceptor.set_option(ip::tcp::acceptor::reuse_address(true));
			m_acceptor.bind(*iterator);
			m_acceptor.listen();
			m_acceptor.async_accept(m_new_connection->get_socket(),
				boost::bind(&bound_port::handle_accept, shared_from_this(), boost::asio::placeholders::error));
		}
		//else if (ec)
		//	m_listener.accept_failed(ec, self);
	});
}

void bound_port::handle_accept(const boost::system::error_code& ec)
{
	//if (ec)
	//	m_listener.accept_failed(ec, this);
	//else
	if (not ec)
	{
		m_new_connection->start();
		m_new_connection = m_connection_factory();
		m_acceptor.async_accept(m_new_connection->get_socket(),
			boost::bind(&bound_port::handle_accept, shared_from_this(), boost::asio::placeholders::error));
	}
}

// --------------------------------------------------------------------

class port_forwarding_connection : public forwarding_connection
{
  public:	

	port_forwarding_connection(std::shared_ptr<connection_base> ssh_connection, const string& remote_addr, int16_t remote_port)
		: forwarding_connection(ssh_connection)
	{
		m_channel.reset(new forwarding_channel(ssh_connection, remote_addr, remote_port));
	}

	virtual void start()
	{
		shared_ptr<forwarding_connection> self(shared_from_this());
		m_channel->async_open([self](const boost::system::error_code& ec)
		{
			if (not ec)
				self->start_copy_data();
		});
	}
};

// --------------------------------------------------------------------

class socks5_forwarding_connection : public forwarding_connection
{
  public:

	socks5_forwarding_connection(std::shared_ptr<connection_base> inConnection)
		: forwarding_connection(inConnection), m_connection(inConnection) {}

	virtual void start();

	void write_error(uint8_t error_code);
	void wrote_error();

	void handshake(const boost::system::error_code& ec, size_t bytes_transferred);
	void channel_open(const boost::system::error_code& ec, const string& remote_address, int16_t remote_port, bool socks4);

	shared_ptr<socks5_forwarding_connection> self() { return dynamic_pointer_cast<socks5_forwarding_connection>(shared_from_this()); }

  private:
	std::shared_ptr<connection_base> m_connection;
	vector<uint8_t> m_buffer;
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
	m_buffer.resize(2);
	m_state = SOCKS_INIT;
	boost::asio::async_read(m_socket, boost::asio::buffer(m_buffer),
							boost::bind(&socks5_forwarding_connection::handshake, self(), boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
}

void socks5_forwarding_connection::handshake(const boost::system::error_code& ec, size_t bytes_transferred)
{
	auto cb = boost::bind(&socks5_forwarding_connection::handshake, self(), boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred);

	switch (m_state)
	{
		case SOCKS_INIT:
			// SOCKS4
			if (m_buffer[0] == '\x04')
			{
				if (m_buffer[1] == 1)	// only allow outbound connections
				{
					m_buffer.resize(6);
					m_state = SOCKS4_INIT;
					boost::asio::async_read(m_socket, boost::asio::buffer(m_buffer), cb);
				}
			}
			else if (m_buffer[0] == '\x05')
			{
				if (m_buffer[1] > 0)
				{
					m_buffer.resize(1);
					m_state = SOCKS5_INIT;
					boost::asio::async_read(m_socket, boost::asio::buffer(m_buffer), cb);
				}
			}
			break;

		case SOCKS4_INIT:
		{
			if (m_buffer[2] == 0 and m_buffer[3] == 0 and m_buffer[4] == 0 and m_buffer[5] != 0)	// SOCKS4a
			{
				m_buffer.resize(2);
				m_state = SOCKS4a_CONNECTION_REQUEST_USER_ID;
				boost::asio::async_read(m_socket, boost::asio::buffer(m_mini_buffer), cb);
			}
			else
			{
				m_state = SOCKS4_CONNECTION_REQUEST_USER_ID;
				boost::asio::async_read(m_socket, boost::asio::buffer(m_mini_buffer), cb);
			}
			break;
		}

		case SOCKS4_CONNECTION_REQUEST_USER_ID:
			if (m_mini_buffer[0] == 0)
			{
				uint8_t* p = m_buffer.data();

				string remote_address;
				int16_t remote_port;

				remote_port = *p++;
				remote_port = (remote_port << 8) | *p++;

				boost::asio::ip::address_v4::bytes_type addr;
				copy(p, p + 4, addr.begin());
				remote_address = boost::lexical_cast<string>(boost::asio::ip::address_v4(addr));

				m_channel.reset(new forwarding_channel(m_connection, remote_address, remote_port));
				m_channel->async_open(boost::bind(&socks5_forwarding_connection::channel_open, self(),
					boost::asio::placeholders::error, remote_address, remote_port, true));
			}
			else
				boost::asio::async_read(m_socket, boost::asio::buffer(m_mini_buffer), cb);
			break;

		case SOCKS4a_CONNECTION_REQUEST_USER_ID:
			if (m_mini_buffer[0] == 0)
				m_state = SOCKS4a_CONNECTION_REQUEST_FQDN;
			boost::asio::async_read(m_socket, boost::asio::buffer(m_mini_buffer), cb);
			break;

		case SOCKS4a_CONNECTION_REQUEST_FQDN:
		{
			if (m_mini_buffer[0] == 0)
			{
				uint8_t* p = m_buffer.data();

				string remote_address(m_buffer.begin() + 2, m_buffer.end());
				int16_t remote_port;

				remote_port = *p++;
				remote_port = (remote_port << 8) | *p++;

				m_channel.reset(new forwarding_channel(m_connection, remote_address, remote_port));

				auto self = shared_from_this();
				m_channel->async_open([self, this, remote_address, remote_port](boost::system::error_code ec, size_t) {
					channel_open(ec, remote_address, remote_port, true);
				});
			}
			else
			{
				m_buffer.push_back(m_mini_buffer[0]);
				boost::asio::async_read(m_socket, boost::asio::buffer(m_mini_buffer), cb);
			}
			break;
		}

		case SOCKS5_INIT:
			if (find(m_buffer.begin(), m_buffer.end(), '\x00') != m_buffer.end())
			{
				m_buffer = { '\x05', '\x00' };
				m_state = SOCKS5_SERVERS_CHOICE;
				boost::asio::async_write(m_socket, boost::asio::buffer(m_buffer), cb);
			}
			break;

		case SOCKS5_SERVERS_CHOICE:
			m_state = SOCKS5_CONNECTION_REQUEST;
			m_buffer.resize(4);
			boost::asio::async_read(m_socket, boost::asio::buffer(m_buffer), cb);
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

				boost::asio::async_read(m_socket, boost::asio::buffer(m_buffer), cb);
			}
			break;

		case SOCKS5_CONNECTION_REQUEST_FQDN:
			m_buffer.resize(m_buffer[0] + 2);
			m_state = SOCKS5_CONNECTION_REQUEST_FQDN_2;
			boost::asio::async_read(m_socket, boost::asio::buffer(m_buffer), cb);
			break;

		case SOCKS5_CONNECTION_REQUEST_IPV4:
		case SOCKS5_CONNECTION_REQUEST_IPV6:
		case SOCKS5_CONNECTION_REQUEST_FQDN_2:
		{
			uint8_t* p = m_buffer.data();

			string remote_address;
			int16_t remote_port;

			switch (m_state)
			{
				case SOCKS5_CONNECTION_REQUEST_IPV4:
				{
					boost::asio::ip::address_v4::bytes_type addr;
					copy(p, p + 4, addr.begin());
					remote_address = boost::lexical_cast<string>(boost::asio::ip::address_v4(addr));
					p += 4;
					break;
				}

				case SOCKS5_CONNECTION_REQUEST_IPV6:
				{
					boost::asio::ip::address_v6::bytes_type addr;
					copy(p, p + 16, addr.begin());
					remote_address = boost::lexical_cast<string>(boost::asio::ip::address_v6(addr));
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
			m_channel->async_open([self, this, remote_address, remote_port](boost::system::error_code ec, size_t) {
				channel_open(ec, remote_address, remote_port, false);
			});
			break;
		}
	}
}

void socks5_forwarding_connection::channel_open(const boost::system::error_code& ec, const string& remote_address, int16_t remote_port, bool socks4)
{
	if (not ec)
	{
		if (socks4)
		{
			m_buffer = { 0, 0x5a, static_cast<uint8_t>(remote_port >> 8), static_cast<uint8_t>(remote_port), 127, 0, 0, 1 };
		}
		else
		{
			m_buffer.resize(4 + 2 + remote_address.length() + 1);
			m_buffer[0] = '\x05';
			m_buffer[1] = '\x00';
			m_buffer[2] = 0;
			m_buffer[3] = '\x03';
			m_buffer[4] = static_cast<uint8_t>(remote_address.length());
			copy(remote_address.begin(), remote_address.end(), m_buffer.begin() + 5);
			m_buffer[m_buffer.size() - 2] = static_cast<uint8_t>(remote_port >> 8);
			m_buffer[m_buffer.size() - 1] = static_cast<uint8_t>(remote_port);
		}

		boost::asio::async_write(m_socket, boost::asio::buffer(m_buffer),
			[](const boost::system::error_code& ec, size_t bytes_transferred) {});

		start_copy_data();
	}
}

void socks5_forwarding_connection::wrote_error()
{
}

//void socks5_forwarding_connection::start()
//{
//	shared_ptr<socks5_forwarding_connection> self(dynamic_pointer_cast<socks5_forwarding_connection>(shared_from_this()));
//	boost::asio::spawn(m_strand, [self](boost::asio::yield_context yield) { self->handshake(yield); });
//}
//
//void socks5_forwarding_connection::handshake(boost::asio::yield_context yield)
//{
//	boost::system::error_code ec;
//	string remote_address;
//	int16_t remote_port;
//	enum { SOCKS4, SOCKS4a, SOCKS5 } version;
//
//	for (;;)
//	{
//		vector<uint8_t> buffer({ 0, 0 });
//
//		size_t l = boost::asio::async_read(m_socket, boost::asio::buffer(buffer), yield[ec]);
//		if (ec or l != 2) break;
//
//		// SOCKS4
//		if (buffer[0] == '\x04')
//		{
//			if (buffer[1] != 1) break;	// only allow outbound connections
//
//			buffer.resize(4);
//			l = boost::asio::async_read(m_socket, boost::asio::buffer(buffer), yield[ec]);
//			if (ec or l != 4) break;
//
//			uint8_t* p = buffer.data();
//
//			remote_port = *p++;
//			remote_port = (remote_port << 8) | *p++;
//
//			if (p[0] == 0 and p[1] == 0 and p[2] == 0 and p[3] != 0)	// SOCKS4a
//			{
//				version = SOCKS4a;
//			}
//			else
//			{
//				boost::asio::ip::address_v4::bytes_type addr;
//				copy(p, p + 4, addr.begin());
//				remote_address = boost::lexical_cast<string>(boost::asio::ip::address_v4(addr));
//
//				version = SOCKS4;
//
//				boost::asio::streambuf b;
//				l = boost::asio::async_read_until(m_socket, b, "\x00", yield);
//			}
//		}
//		else if (buffer[0] == '\x05' and buffer[1] > 0)
//		{
//			version = SOCKS5;
//
//			buffer.resize(buffer[1]);
//			l = boost::asio::async_read(m_socket, boost::asio::buffer(buffer), yield[ec]);
//			if (ec or l != buffer.size()) break;
//
//			if (find(buffer.begin(), buffer.end(), '\x00') == buffer.end())
//				break;
//
//			buffer.resize(2);
//			buffer[0] = '\x05';
//			buffer[1] = '\x00';
//
//			l = boost::asio::async_write(m_socket, boost::asio::buffer(buffer), yield[ec]);
//			if (ec or l != 2) break;
//
//			buffer.resize(4);
//			l = boost::asio::async_read(m_socket, boost::asio::buffer(buffer), yield[ec]);
//			if (ec or l != 4 or buffer[0] != '\x05' or buffer[1] != '\x01' or
//				(buffer[3] != '\x01' and buffer[3] != '\x03' and buffer[3] != '\x04'))
//				break;
//
//			uint8_t atyp = buffer[3];
//			switch (atyp)
//			{
//				case '\x01':
//					buffer.resize(4 + 2);
//					break;
//
//				case '\x04':
//					buffer.resize(16 + 2);
//					break;
//
//				default:
//					buffer.resize(1);
//					break;
//			}
//
//			l = boost::asio::async_read(m_socket, boost::asio::buffer(buffer), yield);
//			if (ec or l != buffer.size()) break;
//
//			if (buffer.size() == 1)
//			{
//				buffer.resize(uint32_t(buffer[0]) + 2);
//
//				l = boost::asio::async_read(m_socket, boost::asio::buffer(buffer), yield);
//				if (ec or l != buffer.size()) break;
//
//				uint8_t* p = buffer.data();
//
//				remote_address.assign(p, p + buffer.size() - 2);
//				p += buffer.size() - 2;
//
//				remote_port = *p++;
//				remote_port = (remote_port << 8) | *p;
//			}
//			else
//			{
//				uint8_t* p = buffer.data();
//
//				switch (atyp)
//				{
//					case '\x01':
//					{
//						boost::asio::ip::address_v4::bytes_type addr;
//						copy(p, p + 4, addr.begin());
//						remote_address = boost::lexical_cast<string>(boost::asio::ip::address_v4(addr));
//						p += 4;
//						break;
//					}
//
//					case '\x04':
//					{
//						boost::asio::ip::address_v6::bytes_type addr;
//						copy(p, p + 16, addr.begin());
//						remote_address = boost::lexical_cast<string>(boost::asio::ip::address_v6(addr));
//						p += 16;
//						break;
//					}
//				}
//
//				remote_port = *p++;
//				remote_port = (remote_port << 8) | *p;
//			}
//		}
//
//		if (remote_address.empty()) break;
//
//		m_channel.reset(new forwarding_channel(m_connection, remote_address, remote_port));
//		m_channel->async_open(yield[ec]);
//
//		if (ec) break;
//
//		if (version == SOCKS5)
//		{
//			buffer.resize(4 + 1 + remote_address.length() + 2);
//			buffer[0] = '\x05';
//			buffer[1] = '\x00';
//			buffer[2] = 0;
//			buffer[3] = '\x03';
//			buffer[4] = static_cast<uint8_t>(remote_address.length());
//			copy(remote_address.begin(), remote_address.end(), buffer.begin() + 5);
//			buffer[buffer.size() - 2] = static_cast<uint8_t>(remote_port >> 8);
//			buffer[buffer.size() - 1] = static_cast<uint8_t>(remote_port);
//		}
//		else if (version == SOCKS4)
//			buffer = { 0, '\x5a', 0, 0 };
//
//		boost::asio::async_write(m_socket, boost::asio::buffer(buffer), yield[ec]);
//		if (ec) break;
//
//		start_copy_data();
//	}
//
//	if (not m_channel and m_socket.is_open())
//	{
//		if (version == SOCKS5)
//		{
//			char buffer[2] = { '\x05', '\xff' };
//			boost::asio::async_write(m_socket, boost::asio::buffer(buffer), yield);
//		}
//		else
//		{
//			char buffer[4] = { 0, 0x5b, 0, 0 };
//			boost::asio::async_write(m_socket, boost::asio::buffer(buffer), yield);
//		}
//	}
//}

// --------------------------------------------------------------------

port_forward_listener::port_forward_listener(std::shared_ptr<connection_base> connection)
	: m_connection(connection)
{
}

port_forward_listener::~port_forward_listener()
{
	//for_each(m_bound_ports.begin(), m_bound_ports.end(), [](bound_port* e) { delete e; });
}

void port_forward_listener::forward_port(const string& local_addr, int16_t local_port,
	const string& remote_address, int16_t remote_port)
{
	shared_ptr<bound_port> p(new bound_port(m_connection, *this,
		[this, remote_address, remote_port]() -> shared_ptr<forwarding_connection>
		{
			return shared_ptr<forwarding_connection>(new port_forwarding_connection(m_connection, remote_address, remote_port));
		}));

	p->listen(local_addr, local_port);
}

void port_forward_listener::forward_socks5(const string& local_addr, int16_t local_port)
{
	shared_ptr<bound_port> p(new bound_port(m_connection, *this,
		[this]() -> shared_ptr<forwarding_connection>
		{
			return shared_ptr<forwarding_connection>(new socks5_forwarding_connection(m_connection));
		}));

	p->listen(local_addr, local_port);
}

//void port_forward_listener::accept_failed(const boost::system::error_code& ec, bound_port* e)
//{
//	//m_bound_ports.erase(remove(m_bound_ports.begin(), m_bound_ports.end(), e), m_bound_ports.end());
//	//delete e;
//}

void port_forward_listener::connection_closed()
{
	//for_each(m_bound_ports.begin(), m_bound_ports.end(), [](bound_port* e) { delete e; });
	//m_bound_ports.clear();
}

}
