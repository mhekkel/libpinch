//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <assh/config.hpp>

#include <boost/bind.hpp>
#include <boost/foreach.hpp>
#define foreach BOOST_FOREACH
#include <boost/lexical_cast.hpp>

#include <assh/port_forwarding.hpp>
#include <assh/connection.hpp>

using namespace std;
namespace ip = boost::asio::ip;

namespace assh
{

// --------------------------------------------------------------------

struct entry
{
	entry(basic_connection& connection, port_forward_listener& listener,
			const string& local_address, uint16 local_port,
			const string& remote_address, uint16 remote_port);

	void	handle_accept(const boost::system::error_code& ec);
	
	basic_connection&					m_connection;
	port_forward_listener&				m_listener;
	ip::tcp::acceptor					m_acceptor;
	ip::tcp::resolver					m_resolver;
	unique_ptr<port_forwarding_channel>	m_new_channel;
	string								m_local_address, m_remote_address;
	uint16								m_local_port, m_remote_port;
};

entry::entry(basic_connection& connection, port_forward_listener& listener,
		const string& local_address, uint16 local_port,
		const string& remote_address, uint16 remote_port)
	: m_connection(connection), m_listener(listener)
	, m_acceptor(connection.get_io_service()), m_resolver(connection.get_io_service())
	, m_local_address(local_address), m_local_port(local_port)
	, m_remote_address(remote_address), m_remote_port(remote_port)
{
	ip::tcp::resolver::query query(m_local_address, boost::lexical_cast<string>(m_local_port));
	m_resolver.async_resolve(query, [this](const boost::system::error_code& ec, ip::tcp::resolver::iterator iterator)
	{
		if (iterator != ip::tcp::resolver::iterator())
		{
			m_new_channel.reset(new port_forwarding_channel(m_connection, m_remote_address, m_remote_port));

			m_acceptor.open(iterator->endpoint().protocol());
			m_acceptor.set_option(ip::tcp::acceptor::reuse_address(true));
			m_acceptor.bind(*iterator);
			m_acceptor.listen();
			m_acceptor.async_accept(m_new_channel->get_socket(),
				boost::bind(&entry::handle_accept, this, boost::asio::placeholders::error));
		}
		else if (ec)
			m_listener.accept_failed(ec, this);
	});
}

void entry::handle_accept(const boost::system::error_code& ec)
{
	if (ec)
		m_listener.accept_failed(ec, this);
	else
	{
		port_forwarding_channel* channel = m_new_channel.release();
		
		if (m_connection.is_connected())
			channel->open();
		else
			delete channel;	// sorry...
		
		m_new_channel.reset(new port_forwarding_channel(m_connection, m_remote_address, m_remote_port));
		m_acceptor.async_accept(m_new_channel->get_socket(),
			boost::bind(&entry::handle_accept, this, boost::asio::placeholders::error));
	}
}

// --------------------------------------------------------------------

port_forward_listener::port_forward_listener(basic_connection& connection)
	: m_connection(connection)
{
}

port_forward_listener::~port_forward_listener()
{
	for_each(m_entries.begin(), m_entries.end(), [](entry* e) { delete e; });
}

void port_forward_listener::forward_port(const string& local_addr, uint16 local_port,
	const string& remote_address, uint16 remote_port)
{
	m_entries.push_back(new entry(m_connection, *this, local_addr, local_port, remote_address, remote_port));
}

void port_forward_listener::accept_failed(const boost::system::error_code& ec, entry* e)
{
	m_entries.erase(remove(m_entries.begin(), m_entries.end(), e), m_entries.end());
	delete e;
}

void port_forward_listener::connection_closed()
{
}

// --------------------------------------------------------------------

port_forwarding_channel::port_forwarding_channel(basic_connection& inConnection,
		const string& remote_address, uint16 remote_port)
	: channel(inConnection)
	, m_socket(inConnection.get_io_service())
	, m_remote_address(remote_address), m_remote_port(remote_port)
{
}

port_forwarding_channel::~port_forwarding_channel()
{
}

void port_forwarding_channel::fill_open_opacket(opacket& out)
{
	channel::fill_open_opacket(out);

	boost::asio::ip::address originator = m_socket.remote_endpoint().address();
	string originator_address = boost::lexical_cast<string>(originator);
	uint16 originator_port = m_socket.remote_endpoint().port();

	out << m_remote_address << uint32(m_remote_port) << originator_address << uint32(originator_port);
}

void port_forwarding_channel::setup(ipacket& in)
{
	// start the read loop
	boost::asio::async_read(m_socket, m_response, boost::asio::transfer_at_least(1),
		boost::bind(&port_forwarding_channel::receive_raw, this,
		boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));

	m_channel_open = true;
}

void port_forwarding_channel::closed()
{
	if (m_socket.is_open())
		m_socket.close();

	channel::closed();
	
	m_connection.get_io_service().post([this]
	{
		delete this;
	});
}

void port_forwarding_channel::receive_data(const char* data, size_t size)
{
	shared_ptr<boost::asio::streambuf> buffer(new boost::asio::streambuf);
	ostream out(buffer.get());
	
	out.write(data, size);
	
	boost::asio::async_write(m_socket, *buffer,
		[this, buffer](const boost::system::error_code& ec, size_t)
		{
			if (ec)
				close();
		});
}

void port_forwarding_channel::receive_raw(const boost::system::error_code& ec, std::size_t bytes_received)
{
	if (ec)
		close();
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
		
		boost::asio::async_read(m_socket, m_response, boost::asio::transfer_at_least(1),
			boost::bind(&port_forwarding_channel::receive_raw, this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
	}
}

}
