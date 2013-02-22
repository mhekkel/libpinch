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
	, m_open_handler(nullptr)
	, m_refcount(1), m_max_send_packet_size(0)
	, m_channel_open(false)
	, m_send_pending(false)
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
	delete m_open_handler;
}

boost::asio::io_service& channel::get_io_service()
{
	return m_connection.get_io_service();
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
	if (m_open_handler)
	{
		(*m_open_handler)(boost::system::error_code());
		delete m_open_handler;
		m_open_handler = nullptr;
	}
}

void channel::close()
{
//	ChannelMessage(_("Channel closed"));
	m_connection.close_channel(this, m_host_channel_id);
}

void channel::closed()
{
	m_channel_open = false;
	for_each(m_pending.begin(), m_pending.end(), [](basic_write_op* op)
	{
		op->written(error::make_error_code(error::connection_lost), 0);
		delete op;
	});
	m_pending.clear();
	
	for_each(m_read_ops.begin(), m_read_ops.end(), [this](basic_read_op* handler)
	{
		handler->post_error(error::make_error_code(error::connection_lost), get_io_service());
		delete handler;
	});
	m_read_ops.clear();
}

void channel::init(ipacket& in, opacket& out)
{
	in >> m_host_window_size >> m_max_send_packet_size;
}

void channel::open_pty(uint32 width, uint32 height,
	const string& terminal_type, bool forward_agent, bool forward_x11)
{
	if (forward_x11)
	{
		opacket out(msg_channel_request);
		out	<< m_host_channel_id
			<< "x11-req"
			<< false << false
			<< "MIT-MAGIC-COOKIE-1"
			<< "0000000000000000"
			<< uint32(0);
		m_connection.async_write(move(out));
	}

	if (forward_agent)
	{
		m_connection.forward_agent(true);
		
		opacket out(msg_channel_request);
		out	<< m_host_channel_id
			<< "auth-agent-req@openssh.com"
			<< false;
		m_connection.async_write(move(out));
	}
	
	opacket out(msg_channel_request);
	out	<< m_host_channel_id
		<< "pty-req"
		<< true				// confirmation, ignore it?
		<< terminal_type
		<< width << height
		<< uint32(0) << uint32(0)
		<< "";
	m_connection.async_write(move(out));
}

void channel::send_request_and_command(
	const string& request, const string& command)
{
	opacket out(msg_channel_request);
	out	<< m_host_channel_id
		<< request
		<< true;
	if (not command.empty())
		out	<< command;
	m_connection.async_write(move(out));
}

void channel::process(ipacket& in)
{
	switch ((message_type)in)
	{
		case msg_channel_open_confirmation:
			in >> m_host_channel_id >> m_host_window_size >> m_max_send_packet_size;
			setup(in);
			break;

		case msg_channel_open_failure:
		{
			uint32 reasonCode;
			string reason;
			
			in >> reasonCode >> reason;
			
//			ChannelError(FormatString("Opening channel failed: ^0", reason));
			m_connection.close_channel(this, 0);
			
			if (m_open_handler)
			{
				(*m_open_handler)(error::make_error_code(error::connection_lost));
				delete m_open_handler;
				m_open_handler = nullptr;
			}

			break;
		}

		case msg_channel_close:
			m_channel_open = false;
			m_connection.close_channel(this, 0);
			break;

		case msg_channel_window_adjust:
		{
			int32 extra;
			in >> extra;
			m_host_window_size += extra;
			send_pending();
			break;
		}
		
		case msg_channel_success:
			if (not m_channel_open)
			{
				m_channel_open = true;
				opened();
			}
			break;

		case msg_channel_data:
			if (m_channel_open)
			{
				pair<const char*,size_t> data;
				in >> data;
				m_my_window_size -= data.second;
				receive_data(data.first, data.second);
			}
			break;

		case msg_channel_extended_data:
			if (m_channel_open)
			{
				uint32 type;
				pair<const char*,size_t> data;
				in >> type >> data;
				m_my_window_size -= data.second;
				receive_extended_data(data.first, data.second, type);
			}
			break;
		
		//case SSH_MSG_CHANNEL_SUCCESS:
		//	HandleChannelEvent(SSH_CHANNEL_SUCCESS);
		//	break;

		//case SSH_MSG_CHANNEL_FAILURE:
		//	HandleChannelEvent(SSH_CHANNEL_FAILURE);
		//	break;

		case msg_channel_request:
		{
			string request;
			bool want_reply;
			
			in >> request >> want_reply;

			opacket out;
			handle_channel_request(request, in, out);
			
			if (want_reply)
			{
				if (out.empty())
					out = opacket(msg_channel_failure) << m_host_channel_id;
				m_connection.async_write(move(out));
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

		opacket out(msg_channel_window_adjust);
		out	<< m_host_channel_id << adjust;
		m_connection.async_write(move(out));
	}
}

void channel::banner(const string& msg, const string& lang)
{
}

void channel::message(const string& msg, const string& lang)
{
}

void channel::error(const string& msg, const string& lang)
{
}

void channel::handle_channel_request(const string& request, ipacket& in, opacket& out)
{
}

void channel::receive_data(ipacket& in)
{
	pair<const char*, size_t> data;
	in >> data;
	receive_data(data.first, data.second);
}

void channel::receive_extended_data(ipacket& in, uint32 type)
{
	pair<const char*, size_t> data;
	in >> data;
	receive_extended_data(data.first, data.second, type);
}

void channel::receive_data(const char* data, size_t size)
{
	m_received.insert(m_received.end(), data, data + size);
	push_received();
}

void channel::receive_extended_data(const char* data, size_t size, uint32 type)
{
}

void channel::send_pending()
{
	while (not m_pending.empty() and not m_send_pending)
	{
		basic_write_op* op = m_pending.front();
		
		if (op->m_packets.empty())
		{
			m_pending.pop_front();
			delete op;
			continue;
		}
		
		size_t size = op->m_packets.front().size();
		if (size > m_host_window_size)
			break;
		
		m_host_window_size -= size;
		m_send_pending = true;

		m_connection.async_write(op->m_packets.front(),
			[this, op](const boost::system::error_code& ec, size_t bytes_transferred)
		{
			this->m_send_pending = false;
			op->m_packets.pop_front();
			if (op->m_packets.empty() or ec)
				op->written(ec, bytes_transferred);
			this->send_pending();
		});
		
		break;
	}
}

void channel::push_received()
{
	boost::asio::io_service& io_service(get_io_service());

	deque<char>::iterator b = m_received.begin();

	while (b != m_received.end() and not m_read_ops.empty())
	{
		basic_read_op* handler = m_read_ops.front();
		m_read_ops.pop_front();

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
