//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <assh/config.hpp>

#include <boost/bind.hpp>
#include <boost/foreach.hpp>
#define foreach BOOST_FOREACH
#include <boost/regex.hpp>
#include <boost/lexical_cast.hpp>

#include <assh/x11_channel.hpp>
#include <assh/connection.hpp>

using namespace std;

namespace assh
{

x11_channel::x11_channel(basic_connection& connection)
	: channel(connection)
	, m_socket(get_io_service())
	, m_verified(false)
{
}

x11_channel::~x11_channel()
{
	if (m_socket.is_open())
		m_socket.close();
}

//void x11_channel::setup(ipacket& in)
//{
//	channel::setup(in);
//	
//	string orig_addr;
//	uint32 orig_port;
//
//	in >> orig_addr >> orig_port;
//}

void x11_channel::opened()
{
	channel::opened();
	
	using boost::asio::ip::tcp;
	
	try
	{
		string host = "localhost", port = "6000";

		const char* display = getenv("DISPLAY");
		boost::regex rx("([-[:alnum:].]*):(\\d+)(?:\\.\\d+)?");

		boost::cmatch m;
		if (display != nullptr and boost::regex_match(display, m, rx))
		{
			if (m[1].matched and not m[1].str().empty())
				host = m[1];
			port = boost::lexical_cast<string>(6000 + boost::lexical_cast<int>(m[2]));
		}

		tcp::resolver resolver(get_io_service());
		tcp::resolver::query query(host, port);
		tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);
		boost::asio::connect(m_socket, endpoint_iterator);

		// start the read loop
		boost::asio::async_read(m_socket, m_response, boost::asio::transfer_at_least(1),
			boost::bind(&x11_channel::receive_raw, this,
			boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
		
		opacket out(msg_channel_open_confirmation);
		out << m_host_channel_id
			<< m_my_channel_id << m_my_window_size << kMaxPacketSize;
		m_connection.async_write(move(out));
		
		m_channel_open = true;
	}
	catch (...)
	{
		opacket out(msg_channel_failure);
		out << m_host_channel_id
			<< 2 << "Failed to open connection to X-server" << "en";
		m_connection.async_write(move(out));
	}
}

void x11_channel::closed()
{
	if (m_socket.is_open())
		m_socket.close();

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
	
	boost::asio::async_write(m_socket, *request,
		[this,request](const boost::system::error_code& ec, size_t)
		{
			if (ec)
				close();
		});
}

bool x11_channel::check_validation()
{
	bool result = false;
	
	if (m_packet.size() >= 12)
	{
		uint16 pl, dl;
		
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
			boost::bind(&x11_channel::receive_raw, this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
	}
}

}
