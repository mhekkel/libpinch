//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <pinch/pinch.hpp>

#include <pinch/channel.hpp>
#include <pinch/connection.hpp>

namespace pinch
{

uint32_t channel::s_next_channel_id = 1;

// channel::channel(std::shared_ptr<basic_connection> inConnection)
// 	: m_connection(inConnection)
// 	, m_open_handler(nullptr)
// 	, m_max_send_packet_size(0)
// 	, m_channel_open(false)
// 	, m_send_pending(false)
// 	, m_my_channel_id(s_next_channel_id++)
// 	, m_host_channel_id(0)
// 	, m_my_window_size(kWindowSize)
// 	, m_host_window_size(0)
// 	, m_eof(false)
// {
// }

// channel::~channel()
// {
// 	assert(not is_open());
	
// 	if (is_open())
// 	{
// 		try
// 		{
// 			close();
// 		}
// 		catch (...) {}
// 	}
	
// 	if (m_open_handler)
// 		m_open_handler->cancel();

// 	// if (m_connection != nullptr)
// 	// 	m_connection->release();

// 	m_open_handler = nullptr;
// 	// delete m_open_handler;
// }

void channel::fill_open_opacket(opacket& out)
{
	out << channel_type() << m_my_channel_id << kWindowSize << kMaxPacketSize;
}

void channel::setup(ipacket& in)
{
	in >> m_host_channel_id >> m_host_window_size >> m_max_send_packet_size;
}

void channel::open()
{
	// if (not m_connection->is_connected())
	// {
	// 	m_connection->async_connect([this](const boost::system::error_code& ec)
	// 	{
	// 		if (ec)
	// 		{
	// 			if (m_open_handler)
	// 				m_open_handler->handle_open_result(ec);
	// 			else
	// 				this->error(ec.message(), "en");
	// 		}
	// 		else
	// 			this->open();
	// 	}, shared_from_this());
	// }
	// else
	// {
		m_my_window_size = kWindowSize;
		m_my_channel_id = s_next_channel_id++;
		m_connection->open_channel(shared_from_this(), m_my_channel_id);
	// }
}

void channel::opened()
{
	if (m_open_handler)
	{
		std::unique_ptr<detail::open_channel_op> handler;
		std::swap(m_open_handler, handler);
		handler->complete(boost::system::error_code(), 0);
	}
}

void channel::close()
{
	if (m_open_handler)
	{
		std::unique_ptr<detail::open_channel_op> handler;
		std::swap(m_open_handler, handler);
		handler->complete(make_error_code(error::by_application), 0);
	}

	m_connection->close_channel(shared_from_this(), m_host_channel_id);
}

void channel::closed()
{
	m_channel_open = false;
	for (auto op: m_read_ops)
	{
		op->complete(error::make_error_code(error::channel_closed));
		delete op;
	}
	m_read_ops.clear();

	for (auto op: m_write_ops)
	{
		op->complete(error::make_error_code(error::channel_closed));
		delete op;
	}
	m_write_ops.clear();
}

// void channel::disconnect(bool disconnectProxy)
// {
// 	m_connection->disconnect();

// 	auto proxy = m_connection->get_proxy();

// 	if (proxy != nullptr and disconnectProxy)
// 		proxy->disconnect();
// }

void channel::succeeded()
{
}

void channel::end_of_file()
{
	m_eof = true;
	// push_received();
}

// void channel::keep_alive()
// {
// 	if (is_open())
// 		m_connection->keep_alive();
// }

// std::string channel::get_connection_parameters(direction dir) const
// {
// 	return is_open() ? m_connection->get_connection_parameters(dir) : "";
// }

// std::string channel::get_key_exchange_algoritm() const
// {
// 	return is_open() ? m_connection->get_key_exchange_algoritm() : "";
// }

void channel::open_pty(uint32_t width, uint32_t height,
	const std::string& terminal_type, bool forward_agent, bool forward_x11,
	const environment& env)
{
	// if (forward_x11)
	// {
	// 	opacket out(msg_channel_request);
	// 	out	<< m_host_channel_id
	// 		<< "x11-req"
	// 		<< false << false
	// 		<< "MIT-MAGIC-COOKIE-1"
	// 		<< "0000000000000000"
	// 		<< uint32_t(0);
	// 	m_connection->async_write(std::move(out));
	// }

	// if (forward_agent)
	// {
	// 	m_connection->forward_agent(true);
		
	// 	opacket out(msg_channel_request);
	// 	out	<< m_host_channel_id
	// 		<< "auth-agent-req@openssh.com"
	// 		<< false;
	// 	m_connection->async_write(std::move(out));
	// }
	
	for (const auto& [name, value]: env)
	{
		opacket out(msg_channel_request);
		out	<< m_host_channel_id
			<< "env"
			<< false
			<< name
			<< value;
		m_connection->async_write(std::move(out));
	}
	
	opacket out(msg_channel_request);
	out	<< m_host_channel_id
		<< "pty-req"
		<< true				// confirmation, ignore it?
		<< terminal_type
		<< width << height
		<< uint32_t(0) << uint32_t(0)
		<< "";
	m_connection->async_write(std::move(out));
}

void channel::send_request_and_command(const std::string& request, const std::string& command)
{
	opacket out(msg_channel_request);
	out	<< m_host_channel_id
		<< request
		<< true;
	if (not command.empty())
		out	<< command;
	m_connection->async_write(std::move(out));
}

void channel::send_signal(const std::string& signal)
{
	opacket out(msg_channel_request);
	out	<< m_host_channel_id
		<< "signal"
		<< false
		<< signal;
	m_connection->async_write(std::move(out));
}

void channel::process(ipacket& in)
{
	switch ((message_type)in)
	{
		case msg_channel_open_confirmation:
			setup(in);
			m_channel_open = true;
			m_eof = false;
			opened();
			break;

		case msg_channel_open_failure:
		{
			uint32_t reasonCode;
			std::string reason;
			
			in >> reasonCode >> reason;
			
			error(reason, "en");

			m_connection->close_channel(shared_from_this(), 0);
			
			if (m_open_handler)
			{
				auto handler = std::move(m_open_handler);
				handler->complete(error::make_error_code(error::connection_lost));
			}

			break;
		}

		case msg_channel_close:
			closed();
			m_connection->close_channel(shared_from_this(), 0);
			break;

		case msg_channel_success:
			succeeded();
			break;

		case msg_channel_window_adjust:
		{
			int32_t extra;
			in >> extra;
			m_host_window_size += extra;
			send_pending();
			break;
		}
		
		case msg_channel_data:
			if (m_channel_open)
			{
				std::pair<const char*,size_t> data;
				in >> data;
				m_my_window_size -= data.second;
				receive_data(data.first, data.second);
			}
			break;

		case msg_channel_extended_data:
			if (m_channel_open)
			{
				uint32_t type;
				std::pair<const char*,size_t> data;
				in >> type >> data;
				m_my_window_size -= data.second;
				receive_extended_data(data.first, data.second, type);
			}
			break;
		
		case msg_channel_eof:
			end_of_file();
			break;

		case msg_channel_request:
		{
			std::string request;
			bool want_reply = false;
			
			in >> request >> want_reply;

			opacket out;
			handle_channel_request(request, in, out);
			
			if (want_reply)
			{
				if (out.empty())
					out = opacket(msg_channel_failure) << m_host_channel_id;
				m_connection->async_write(std::move(out));
			}
			break;
		}
		
		default:
			//PRINT(("Unhandled channel message %d", inMessage));
			;
	}

	if (m_channel_open and m_my_window_size < kWindowSize - 2 * kMaxPacketSize)
	{
		uint32_t adjust = kWindowSize - m_my_window_size;
		m_my_window_size += adjust;

		opacket out(msg_channel_window_adjust);
		out	<< m_host_channel_id << adjust;
		m_connection->async_write(std::move(out));
	}
}

void channel::banner(const std::string& msg, const std::string& lang)
{
	if (m_banner_handler)
		m_banner_handler(msg, lang);
}

void channel::message(const std::string& msg, const std::string& lang)
{
	if (m_message_handler)
		m_message_handler(msg, lang);
}

void channel::error(const std::string& msg, const std::string& lang)
{
	if (m_error_handler)
		m_error_handler(msg, lang);
}

void channel::handle_channel_request(const std::string& request, ipacket& in, opacket& out)
{
}

void channel::receive_data(const char* data, size_t size)
{
	m_received.insert(m_received.end(), data, data + size);
	push_received();
}

void channel::receive_extended_data(const char* data, size_t size, uint32_t type)
{
}

void channel::send_pending()
{
	while (not m_write_ops.empty() and not m_send_pending)
	{
		auto op = m_write_ops.front();
		
		if (op->empty())
		{
			m_write_ops.pop_front();
			op->complete(boost::system::error_code(), 0);
			delete op;
			continue;
		}
		
		size_t size = op->front_size() - 9;
		if (size > m_host_window_size)
			break;
		
		m_host_window_size -= size;
		m_send_pending = true;

		m_connection->async_write(op->pop_front(),
			[
				this,
				self = shared_from_this(),
				op
			]
			(const boost::system::error_code& ec, size_t bytes_transferred)
			{
				m_send_pending = false;

				if (ec or op->empty())
				{
					op->complete(ec, bytes_transferred);
					delete op;
					m_write_ops.pop_front();
				}

				send_pending();
			});
		
		break;
	}
}

void channel::push_received()
{
	auto b = m_received.begin();

	while (b != m_received.end() and not m_read_ops.empty())
	{
		auto handler = m_read_ops.front();
		m_read_ops.pop_front();

		b = handler->transfer_bytes(b, m_received.end());
		handler->complete();

		delete handler;
	}

	m_received.erase(m_received.begin(), b);
	
	if (m_received.empty() and m_eof)
		close();
}

// // --------------------------------------------------------------------

// void exec_channel::opened()
// {
// 	channel::opened();

// 	send_request_and_command("exec", m_command);
// }

// void exec_channel::handle_channel_request(const std::string& request, ipacket& in, opacket& out)
// {
// 	int32_t status = 1;
	
// 	if (request == "exit-status")
// 		in >> status;
	
// 	m_handler->post_result(request, status);
// }

}
