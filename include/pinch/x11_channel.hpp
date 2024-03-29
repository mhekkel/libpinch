//        Copyright Maarten L. Hekkelman 2013-2021
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include "pinch/channel.hpp"

namespace pinch
{

// --------------------------------------------------------------------

struct x11_socket_impl_base;

class x11_channel : public channel
{
  public:
	x11_channel(std::shared_ptr<basic_connection> inConnection);
	~x11_channel();

	void receive_raw(const asio_system_ns::error_code &ec, std::size_t bytes_received);

  protected:
	virtual void opened();
	virtual void closed();

	virtual void receive_data(const char *data, std::size_t size);
	bool check_validation();

	std::unique_ptr<x11_socket_impl_base> m_impl;
	bool m_verified;
	std::string m_auth_protocol, m_auth_data;
	blob m_packet;
	asio_ns::streambuf m_response;
};

} // namespace pinch
