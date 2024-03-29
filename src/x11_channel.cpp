//        Copyright Maarten L. Hekkelman 2013-2021
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include "pinch/connection.hpp"
#include "pinch/debug.hpp"
#include "pinch/x11_channel.hpp"

#include <regex>

namespace pinch
{

struct x11_socket_impl_base
{
	virtual ~x11_socket_impl_base() = default;

	virtual void async_read(std::shared_ptr<x11_channel> channel, asio_ns::streambuf &response) = 0;
	virtual void async_write(channel_ptr channel, std::shared_ptr<asio_ns::streambuf> data) = 0;
};

template <class SOCKET>
struct x11_socket_impl : public x11_socket_impl_base
{
	template <typename Arg>
	x11_socket_impl(Arg &&arg)
		: m_socket(std::forward<Arg>(arg))
	{
	}

	~x11_socket_impl()
	{
		if (m_socket.is_open())
			m_socket.close();
	}

	virtual void async_read(std::shared_ptr<x11_channel> channel, asio_ns::streambuf &response)
	{
		asio_ns::async_read(m_socket, response, asio_ns::transfer_at_least(1),
			[channel](const asio_system_ns::error_code &ec, std::size_t bytes_transferred)
			{
				channel->receive_raw(ec, bytes_transferred);
			});
	}

	virtual void async_write(channel_ptr channel, std::shared_ptr<asio_ns::streambuf> data)
	{
		asio_ns::async_write(m_socket, *data,
			[channel, data](const asio_system_ns::error_code &ec, size_t)
			{
				if (ec)
					channel->close();
			});
	}

	SOCKET m_socket;
};

struct x11_datagram_impl : public x11_socket_impl<asio_ns::ip::tcp::socket>
{
	template <typename Arg>
	x11_datagram_impl(Arg &&arg, const std::string &host, const std::string &port)
		: x11_socket_impl(std::forward<Arg>(arg))
	{
		using asio_ns::ip::tcp;

		tcp::resolver resolver(arg);
		auto endpoints = resolver.resolve(host, port);
		asio_ns::connect(m_socket, endpoints);
	}
};

struct x11_stream_impl : public x11_socket_impl<asio_ns::local::stream_protocol::socket>
{
	template <typename Arg>
	x11_stream_impl(Arg &&arg, const std::string &display_nr)
		: x11_socket_impl(std::forward<Arg>(arg))
	{
		const std::string kXUnixPath("/tmp/.X11-unix/X");

		m_socket.connect(asio_ns::local::stream_protocol::endpoint(kXUnixPath + display_nr));
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
		std::string host = "localhost", port = "6000";

		const char *display = getenv("DISPLAY");
		std::regex rx("([-[:alnum:].]*):(\\d+)(?:\\.\\d+)?");

		std::cmatch m;
		if (display != nullptr and std::regex_match(display, m, rx))
		{
			host = m[1];
			port = m[2];
		}

		if (host.empty())
			m_impl.reset(new x11_stream_impl(get_executor(), port));
		else
			m_impl.reset(new x11_datagram_impl(get_executor(), host, std::to_string(6000 + stoi(port))));

		// start the read loop
		std::shared_ptr<x11_channel> self(std::dynamic_pointer_cast<x11_channel>(shared_from_this()));
		m_impl->async_read(self, m_response);

		opacket out(msg_channel_open_confirmation);
		out << m_host_channel_id
			<< m_my_channel_id << m_my_window_size << kMaxPacketSize;
		m_connection->async_write(std::move(out));

		m_channel_open = true;
	}
	catch (...)
	{
		opacket out(msg_channel_failure);
		out << m_host_channel_id
			<< 2 << "Failed to open connection to X-server"
			<< "en";
		m_connection->async_write(std::move(out));
	}
}

void x11_channel::closed()
{
	m_impl.reset(nullptr);
	channel::closed();
}

void x11_channel::receive_data(const char *data, size_t size)
{
	std::shared_ptr<asio_ns::streambuf> request(new asio_ns::streambuf);
	std::ostream out(request.get());

	if (m_verified)
		out.write(data, size);
	else
	{
		m_packet.insert(m_packet.end(), data, data + size);

		m_verified = check_validation();

		if (m_verified and not m_packet.empty())
		{
			out.write(reinterpret_cast<const char *>(m_packet.data()), m_packet.size());
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
		uint16_t pl, dl;

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

		std::string protocol, data;

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

void x11_channel::receive_raw(const asio_system_ns::error_code &ec, size_t size)
{
	if (ec)
		close();
	else
	{
		std::istream in(&m_response);
		std::shared_ptr<x11_channel> self(std::dynamic_pointer_cast<x11_channel>(shared_from_this()));

		for (;;)
		{
			char buffer[8192];

			size_t k = static_cast<size_t>(in.readsome(buffer, sizeof(buffer)));
			if (k == 0)
				break;

			asio_ns::async_write(*this, asio_ns::buffer(buffer, k),
				[self](const asio_system_ns::error_code &ec, size_t)
				{
					if (ec)
						self->close();
				});
		}

		if (m_impl)
			m_impl->async_read(self, m_response);
	}
}

} // namespace pinch
