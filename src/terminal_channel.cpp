//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <pinch/pinch.hpp>

#include <pinch/packet.hpp>
#include <pinch/terminal_channel.hpp>
#include <pinch/connection.hpp>

using namespace std;

namespace pinch
{

terminal_channel::terminal_channel(std::shared_ptr<connection_base> connection)
	: channel(connection)
	, m_width(80)
	, m_height(24)
	, m_terminal_type("xterm")
	, m_forward_agent(false)
	, m_forward_x11(false)
{
}

void terminal_channel::set_environment_variable(
	const string& name, const string& value)
{
	environment_variable v = { name, value };
	m_env.push_back(v);
}

void terminal_channel::opened()
{
	channel::opened();
	
	open_pty(m_width, m_height, m_terminal_type, m_forward_agent, m_forward_x11, m_env);
	if (m_command.empty())
		send_request_and_command("shell", "");
	else
		send_request_and_command("exec", m_command);
}

void terminal_channel::open_with_pty(uint32_t width, uint32_t height,
	const string& terminal_type, bool forward_agent, bool forward_x11,
	const string& ssh_command)
{
	m_width = width;
	m_height = height;
	m_terminal_type = terminal_type;
	m_forward_agent = forward_agent;
	m_forward_x11 = forward_x11;
	m_command = ssh_command;
	
	open();
}

void terminal_channel::send_window_resize(uint32_t width, uint32_t height)
{
	opacket out(msg_channel_request);
	out << m_host_channel_id
		<< "window-change" << false
		<< width << height
		<< uint32_t(0) << uint32_t(0);
	m_connection->async_write(move(out));
}
	
}
