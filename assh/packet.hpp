//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include <assh/config.hpp>

#include <vector>

#include <boost/asio.hpp>
#include <cryptopp/integer.h>

namespace assh
{
	
enum message_type : uint8
{
	undefined,

	disconnect = 1, ignore, unimplemented, debug, service_request, service_accept,

	kexinit = 20, newkeys,

	kexdh_init = 30, kexdh_reply,

 	userauth_request = 50, userauth_failure, userauth_success, userauth_banner,

	userauth_info_request = 60, userauth_info_response,

	global_request = 80, request_success, request_failure,

	channel_open = 90, channel_open_confirmation, channel_open_failure,
	channel_window_adjust, channel_data, channel_extended_data,
	channel_eof, channel_close, channel_request, channel_success,
	channel_failure,
};

class packet
{
  public:
	virtual			~packet();

	message_type	message() const					{ return m_message; }
					operator message_type() const	{ return m_message; }

	void			to_buffers(uint32 blocksize, std::vector<boost::asio::const_buffer>& buffers);

	template<typename MutableBufferSequence>
	static packet*	create(const MutableBufferSequence& buffers);

  protected:
					packet(message_type message) : m_message(message), m_padding(nullptr) {}

	virtual void	add_data(std::vector<boost::asio::const_buffer>& buffers) const;

	message_type	m_message;
	uint8			m_header[5];
	uint8*			m_padding;
};

class disconnect_packet : public packet
{
  public:
					disconnect_packet()
						: packet(disconnect) {}
};




}
