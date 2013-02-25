//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <assh/config.hpp>

#include <boost/bind.hpp>
#include <boost/foreach.hpp>
#define foreach BOOST_FOREACH

#include <assh/x11_channel.hpp>

using namespace std;

namespace assh
{

x11_channel::x11_channel(basic_connection& connection)
	: channel(connection)
	, m_socket(connection::get_io_service())
	, m_verified(false)
{
}

x11_channel::~x11_channel()
{
	if (m_socket.is_open())
		m_socket.close();

	foreach (boost::asio::streambuf* buffer, mRequests)
		delete buffer;

	mRequests.clear();
}

void x11_channel::setup(ipacket& in)
{
	using boost::asio::ip::tcp;

	string orig_addr;
	uint32 orig_port;

	in >> orig_addr >> orig_port;
	
	// 
	
	try
	{
#pragma message("Get info from DISPLAY")

		tcp::resolver resolver(get_io_service());
		tcp::resolver::query query("localhost", "6000");
		tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);
		boost::asio::connect(m_socket, endpoint_iterator);

		// start the read loop
		boost::asio::async_read(m_socket, m_response, boost::asio::transfer_at_least(1),
			boost::bind(&x11_channel::receive_raw, this,
			boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
		
		m_connection.send(opacket(msg_channel_open_confirmation) << m_host_channel_id
			<< m_my_channel_id << m_my_window_size << kMaxPacketSize);
		
		m_channel_open = true;
	}
	catch (...)
	{
		m_connection.send(opacket(msg_channel_failure) << m_host_channel_id
			<< 2 << "Failed to open connection to X-server" << "en");
	}
}

void x11_channel::Closed()
{
	if (m_socket.is_open())
		m_socket.close();

	channel::closed();
}

void x11_channel::ReceiveData(MSshPacket& inData)
{
	mRequests.push_back(new boost::asio::streambuf);
	ostream out(mRequests.back());
	
	if (m_verified)
		out.write(reinterpret_cast<const char*>(inData.peek()), inData.size());
	else
	{
		const uint8* data = inData.peek();
		uint32 size = inData.size();
		
		m_packet.insert(m_packet.end(), data, data + size);
		
		m_verified = CheckValidation();
		
		if (m_verified and not m_packet.empty())
		{
			out.write(reinterpret_cast<const char*>(&m_packet[0]), m_packet.size());
			m_packet.clear();
		}
	}
	
	boost::asio::async_write(m_socket, *mRequests.back(),
		boost::bind(&x11_channel::PacketSent, this, boost::asio::placeholders::error));
}

void x11_channel::PacketSent(const boost::system::error_code& err)
{
	if (not mRequests.empty())
	{
		delete mRequests.front();
		mRequests.pop_front();
	}
	
	if (err)
		Close();
}

bool x11_channel::CheckValidation()
{
	bool result = false;
	
	if (m_packet.size() > 12)
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
		
		if (m_packet.size() >= 12 + pl + dl)
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

void x11_channel::receive_raw(const boost::system::error_code& err, size_t)
{
	if (err)
	{
		Close();
		Release();
		return;
	}
	
	istream in(&mResponse);

	for (;;)
	{
		char buffer[1024];

		size_t k = in.readsome(buffer, sizeof(buffer));
		if (k == 0)
			break;

		MSshPacket p;
		p << uint8(SSH_MSG_CHANNEL_DATA) << mHostChannelID << string(buffer, buffer + k);
		PushPending(p);
	}
	
	boost::asio::async_read(m_socket, mResponse, boost::asio::transfer_at_least(1),
		boost::bind(&x11_channel::ReceiveRaw, this, boost::asio::placeholders::error));
}

}
