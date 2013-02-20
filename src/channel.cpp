//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <assh/config.hpp>

#include <assh/channel.hpp>
#include <assh/connection.hpp>

using namespace std;
using namespace CryptoPP;

namespace assh
{

uint32 channel::s_next_channel_id = 1;

channel::channel(basic_connection& inConnection)
	: m_connection(inConnection)
	, m_refcount(1), m_max_send_packet_size(0)
	, m_channel_open(false)
	, m_my_channel_id(s_next_channel_id++)
	, m_host_channel_id(0)
	, m_my_window_size(kWindowSize)
	, m_host_window_size(0)
{
}

channel::~channel()
{
#if DEBUG
	assert(m_refcount == 0);
#endif
}

void channel::reference()
{
	++m_refcount;
}

void channel::release()
{
	if (--m_refcount == 0)
		delete_this();
}

void channel::delete_this()
{
	delete this;
}

//string channel::GetEncryptionParams() const
//{
//	return m_connection.GetEncryptionParams();
//}
//
//string channel::GetHostVersion() const
//{
//	return m_connection.GetHostVersion();
//}

void channel::open()
{
	m_my_window_size = kWindowSize;
	m_my_channel_id = s_next_channel_id++;
	m_connection.open_channel(this, m_my_channel_id);
}

void channel::opened()
{
}

void channel::close()
{
//	ChannelMessage(_("Channel closed"));
	m_connection.close_channel(this, m_host_channel_id);
}

void channel::closed()
{
	m_channel_open = false;
}

void channel::open_pty(uint32 with, uint32 height,
	const string& terminal_type, bool forward_agent, bool forward_x11)
{
	if (forward_x11)
	{
		send(opacket(channel_request)
			<< m_host_channel_id
			<< "x11-req"
			<< false << false
			<< "MIT-MAGIC-COOKIE-1"
			<< "0000000000000000"
			<< uint32(0));
	}

	if (forward_agent)
	{
//		m_connection.SetForwardAgent(true);
		
		m_connection.Send(opacket(channel_request)
			<< m_host_channel_id
			<< "auth-agent-req@openssh.com"
			<< false);
	}
	
	m_connection.send(opacket(channel_request)
		<< m_host_channel_id
		<< "pty-req"
		<< true				// confirmation, ignore it?
		<< inTerminalType
		<< inWidth << inHeight
		<< uint32(0) << uint32(0)
		<< "");
}

void channel::send_request_and_command(
	const string& request, const string& command)
{
	m_connection.send(opacket(channel_request)
		<< m_host_channel_id
		<< inRequest
		<< true
		<< inCommand);
}

void channel::process(ipacket& in)
{
	switch ((message_type)inMessage)
	{
		case channel_open_confirmation:
			in >> m_host_channel_id >> m_host_window_size >> m_max_send_packet_size;
			Setup(in);
			break;

		case channel_open_failure:
		{
			uint32 reasonCode;
			string reason;
			
			in >> reasonCode >> reason;
			
//			ChannelError(FormatString("Opening channel failed: ^0", reason));
			m_connection.close_channel(this, 0);
			break;
		}

		case channel_close:
			m_channel_open = false;
			m_connection.close_channel(this, 0);
			break;

		case channel_window_adjust:
		{
			int32 extra;
			in >> extra;
			m_host_window_size += extra;
			break;
		}
		
		case channel_success:
			if (not m_channel_open)
			{
				m_channel_open = true;
				opened();
			}
			break;

		case channel_data:
		{
			uint32 l;
			in >> l;
			m_my_window_size -= l;
			in.resize(l);
			
			if (m_channel_open)
				received_data(in);
			break;
		}

		case SSH_MSG_CHANNEL_EXTENDED_DATA:
		{
			uint32 l;
			in >> l;
			m_my_window_size -= l;
			in.resize(l);

			if (m_channel_open)
				ReceiveExtendedData(in, type);
			break;
		}
		
		//case SSH_MSG_CHANNEL_SUCCESS:
		//	HandleChannelEvent(SSH_CHANNEL_SUCCESS);
		//	break;

		//case SSH_MSG_CHANNEL_FAILURE:
		//	HandleChannelEvent(SSH_CHANNEL_FAILURE);
		//	break;

		case SSH_MSG_CHANNEL_REQUEST:
		{
			string request;
			bool want_reply;
			
			in >> request >> want_reply;

			opacket out;
			handle_channel_request(request, in, out);
			
			if (want_reply)
			{
				if (out.empty())
					out = opacket(channel_failure) << m_host_channel_id;
				m_connection.send(out);
			}
			break;
		}
		
		default:
			//PRINT(("Unhandled channel message %d", inMessage));
			;
	}

	if (m_channel_open and m_my_window_size < kWindowSize - 2 * kMaxPacketSize)
	{
		uint32 adjust = kWindowSize - m_my_window_size;
		m_my_window_size += adjust;
		m_connection.send(out(channel_window_adjust)
			<< m_host_channel_id << adjust);
	}
}

void channel::send(opacket& p)
{
	m_connection.send(p);
}

void channel::send_data(const char* data, size_t size)
{
	assert(data.size() <= m_max_send_packet_size);
	push(opacket(channel_data) << m_host_channel_id << make_pair(data, size));
}

void channel::send_data(opacket& data)
{
	assert(data.size() <= m_max_send_packet_size);
	push(opacket(channel_data) << m_host_channel_id << data);
}

void channel::send_extended_data(opacket& data, uint32 type)
{
	assert(data.size() < m_max_send_packet_size);
	push(opacket(channel_extended_data) << m_host_channel_id << type << data);
}

void channel::banner(const string& msg)
{
}

void channel::message(const string& msg)
{
}

void channel::error(const string& msg)
{
}

void channel::handle_channel_request(const string& request, ipacket& in, opacket& out)
{
}

void channel::received_data(ipacket& in)
{
	pair<const char*, size_t> data;
	in >> data;
	received_data(data.first, data.second);
}

void channel::receive_extended_data(ipacket& in, uint32 type)
{
	pair<const char*, size_t> data;
	in >> data;
	receive_extended_data(data.first, data.second);
}

void channel::received_data(const char* data, size_t size)
{
	m_received.insert(m_received.end(), data, data + size);
	push_received();
}

void channel::receive_extended_data(const char* data, size_t size, uint32 type)
{
}

opacket channel::pop()
{
	opacket result;
	
	if (not m_pending.empty() and m_pending.front().size() < m_host_window_size)
	{
		result = true;
		result = move(m_pending.front());
		m_pending.pop_front();
		m_host_window_size -= result.size();
	}
	
	return result;
}
	
void channel::push(opacket& data)
{
	// see if we can send this packet right away instead of 
	// having to queue it.
	if (m_pending.empty() and data.size() < m_host_window_size)
	{
		m_connection.send(data);
		m_host_window_size -= data.size();
	}
	else
		m_pending.push_back(data);
}

void channel::push_received()
{
	boost::asio::io_service& io_service(get_io_service());

	deque<char>::iterator b = m_received.begin();

	while (b != m_received.end() and not m_read_handlers.empty())
	{
		basic_read_handler* handler = m_read_handlers.front();
		m_read_handlers.pop_front();

		b = handler->receive_and_post(b, m_received.end(), io_service);

		delete handler;
	}

	m_received.erase(m_received.begin(), b);
}

//// --------------------------------------------------------------------
//
//MSshExecChannel::MSshExecChannel(const string& inHost, const string& inUser,
//	uint16 inPort, const string& inCommand, ResultHandler inResultHandler)
//	: channel(*basic_connection::Get(inHost, inUser, inPort))
//	, mCommand(inCommand)
//	, mHandler(inResultHandler)
//{
//}
//
//MSshExecChannel::MSshExecChannel(basic_connection* inConnection,
//		const string& inCommand, ResultHandler inResultHandler)
//	: channel(*inConnection)
//	, mCommand(inCommand)
//	, mHandler(inResultHandler)
//{
//}
//
//void MSshExecChannel::Setup(MSshPacket& in)
//{
//	SendRequestAndCommand("exec", mCommand);
//}
//
//void MSshExecChannel::HandleChannelRequest(const string& inRequest, MSshPacket& in, MSshPacket& out)
//{
//	uint32 status = 1;
//	
//	if (inRequest == "exit-status")
//		in >> status;
//	
//	mHandler(inRequest, status);
//}


}
