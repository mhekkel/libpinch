//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <assh/config.hpp>

#include <boost/bind.hpp>
#include <boost/regex.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/asio/local/stream_protocol.hpp>

#include <assh/x11_channel.hpp>
#include <assh/connection.hpp>

using namespace std;

namespace assh
{

struct x11_socket_impl_base
{
	virtual ~x11_socket_impl_base() {}

	virtual void async_read(shared_ptr<x11_channel> channel, boost::asio::streambuf& response) = 0;
	virtual void async_write(channel_ptr channel, shared_ptr<boost::asio::streambuf> data) = 0;
};

template<class SOCKET>
struct x11_socket_impl : public x11_socket_impl_base
{
	x11_socket_impl(boost::asio::io_service& io_service)
		: m_socket(io_service) {}

	~x11_socket_impl()
	{
		if (m_socket.is_open())
			m_socket.close();
	}

	virtual void async_read(shared_ptr<x11_channel> channel, boost::asio::streambuf& response)
	{
		boost::asio::async_read(m_socket, response, boost::asio::transfer_at_least(1),
			boost::bind(&x11_channel::receive_raw, channel,
			boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
	}
	
	virtual void async_write(channel_ptr channel, shared_ptr<boost::asio::streambuf> data)
	{
		boost::asio::async_write(m_socket, *data,
			[channel,data](const boost::system::error_code& ec, size_t)
			{
				if (ec)
					channel->close();
			});
	}

	SOCKET m_socket;
};

struct x11_datagram_impl : public x11_socket_impl<boost::asio::ip::tcp::socket>
{
	x11_datagram_impl(boost::asio::io_service& io_service, const string& host, const string& port)
		: x11_socket_impl(io_service)
	{
		using boost::asio::ip::tcp;

		tcp::resolver resolver(io_service);
		tcp::resolver::query query(host, port);
		tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);
		boost::asio::connect(m_socket, endpoint_iterator);
	}
	
};

struct x11_stream_impl : public x11_socket_impl<boost::asio::local::stream_protocol::socket>
{
	x11_stream_impl(boost::asio::io_service& io_service, const string& display_nr)
		: x11_socket_impl(io_service)
	{
		const std::string kXUnixPath("/tmp/.X11-unix/X");
		
		m_socket.connect(boost::asio::local::stream_protocol::endpoint(kXUnixPath + display_nr));
	}
};

x11_channel::x11_channel(std::shared_ptr<basic_connection> connection)
	: channel(connection)
	, m_verified(false)
{
}

x11_channel::~x11_channel()
{
}

void x11_channel::opened()
{
	channel::opened();
	
	try
	{
		string host = "localhost", port = "6000";

		const char* display = getenv("DISPLAY");
		boost::regex rx("([-[:alnum:].]*):(\\d+)(?:\\.\\d+)?");

		boost::cmatch m;
		if (display != nullptr and boost::regex_match(display, m, rx))
		{
			host = m[1];
			port = m[2];
		}
		
		if (host.empty())
			m_impl.reset(new x11_stream_impl(get_io_service(), port));
		else
			m_impl.reset(new x11_datagram_impl(get_io_service(), host, to_string(6000 + stoi(port))));

		// start the read loop
		shared_ptr<x11_channel> self(dynamic_pointer_cast<x11_channel>(shared_from_this()));
		m_impl->async_read(self, m_response);
		
		opacket out(msg_channel_open_confirmation);
		out << m_host_channel_id
			<< m_my_channel_id << m_my_window_size << kMaxPacketSize;
		m_connection->async_write(move(out));
		
		m_channel_open = true;
	}
	catch (...)
	{
		opacket out(msg_channel_failure);
		out << m_host_channel_id
			<< 2 << "Failed to open connection to X-server" << "en";
		m_connection->async_write(move(out));
	}
}

void x11_channel::closed()
{
	m_impl.reset(nullptr);
	channel::closed();
}

void x11_channel::receive_data(const char* data, size_t size)
{
	shared_ptr<boost::asio::streambuf> request(new boost::asio::streambuf);
	ostream out(request.get());
	
	if (m_verified)
		out.write(data, size);
	else
	{
		m_packet.insert(m_packet.end(), data, data + size);
		
		m_verified = check_validation();
		
		if (m_verified and not m_packet.empty())
		{
			out.write(reinterpret_cast<const char*>(&m_packet[0]), m_packet.size());
			m_packet.clear();
		}
	}
	
	if (m_impl)
		m_impl->async_write(shared_from_this(), request);
}

bool x11_channel::check_validation()
{
	bool result = false;
	
	if (m_packet.size() >= 12)
	{
		int16_t pl, dl;
		
		if (m_packet.front() == 'B')
		{
			pl = m_packet[6] << 8 | m_packet[7];
			dl = m_packet[8] << 8 | m_packet[9];
		}
		else
		{
			pl = m_packet[7] << 8 | m_packet[6];
			dl = m_packet[9] << 8 | m_packet[8];
		}
		
		dl += dl % 4;
		pl += pl % 4;
		
		string protocol, data;
		
		if (m_packet.size() >= 12UL + pl + dl)
		{
			protocol.assign(m_packet.begin() + 12, m_packet.begin() + 12 + pl);
			data.assign(m_packet.begin() + 12 + pl, m_packet.begin() + 12 + pl + dl);
		}
		
		// we accept anything.... duh
		m_packet[6] = m_packet[7] = m_packet[8] = m_packet[9] = 0;
		
		// strip out the protocol and data 
		if (pl + dl > 0)
			m_packet.erase(m_packet.begin() + 12, m_packet.begin() + 12 + pl + dl);

		result = true;
	}
	
	return result;
}

void x11_channel::receive_raw(const boost::system::error_code& ec, size_t)
{
	if (ec)
		close();
	else
	{
		istream in(&m_response);
		shared_ptr<x11_channel> self(dynamic_pointer_cast<x11_channel>(shared_from_this()));
	
		for (;;)
		{
			char buffer[8192];
	
			size_t k = static_cast<size_t>(in.readsome(buffer, sizeof(buffer)));
			if (k == 0)
				break;
			
			send_data(buffer, k,
				[self](const boost::system::error_code& ec, size_t)
				{
					if (ec)
						self->close();
				});
		}
		
		if (m_impl)
			m_impl->async_read(self, m_response);
	}
}

}
