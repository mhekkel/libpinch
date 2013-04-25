//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <assh/config.hpp>

#include <assh/packet.hpp>
#include <assh/terminal_channel.hpp>
#include <assh/connection.hpp>

using namespace std;

namespace assh
{

terminal_channel::terminal_channel(basic_connection& connection)
	: channel(connection)
	, m_width(80)
	, m_height(24)
	, m_terminal_type("vt220")
	, m_forward_agent(false)
	, m_forward_x11(false)
{
}

void terminal_channel::opened()
{
	channel::opened();
	
	open_pty(m_width, m_height, m_terminal_type, m_forward_agent, m_forward_x11);
	send_request_and_command("shell", "");
}

void terminal_channel::open_with_pty(uint32 width, uint32 height,
	const string& terminal_type, bool forward_agent, bool forward_x11)
{
	m_width = width;
	m_height = height;
	m_terminal_type = terminal_type;
	m_forward_agent = forward_agent;
	m_forward_x11 = forward_x11;
	
	open();
}

void terminal_channel::send_window_resize(uint32 width, uint32 height)
{
	opacket out(msg_channel_request);
	out << m_host_channel_id
		<< "window-change" << false
		<< width << height
		<< uint32(0) << uint32(0);
	m_connection.async_write(move(out));
}
	
}
