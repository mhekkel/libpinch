//        Copyright Maarten L. Hekkelman 2013-2021
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include <pinch/pinch.hpp>
#include <pinch/connection.hpp>
#include <pinch/channel.hpp>

namespace pinch
{

class basic_connection;

// --------------------------------------------------------------------
// ssh_agent_channel is used for forwarding the ssh-agent over a connection

class ssh_agent_channel : public channel
{
  public:
	ssh_agent_channel(std::shared_ptr<basic_connection> connection);
	virtual ~ssh_agent_channel();

	virtual void opened();
	virtual void receive_data(const char *data, std::size_t size);

  private:
	ipacket m_packet;
};

}