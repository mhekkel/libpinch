//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include <iostream>

#include <boost/asio.hpp>
#include <boost/algorithm/string.hpp>

#include <assh/packet.hpp>
#include <assh/error.hpp>

namespace assh
{

template<typename SOCKET>
class basic_connection
{
  public:
	typedef SOCKET									socket_type;

	typedef std::shared_ptr<boost::asio::streambuf>	streambuf_ptr;

					basic_connection(socket_type& socket)
						: m_socket(socket)
					{
					}

					~basic_connection()
					{
					}


	template<typename Handler>
	struct connect_op
	{
		typedef void (basic_connection::*next_type)(Handler&);
		
					connect_op(basic_connection& connection, next_type next, Handler& hander)
						: m_connection(connection), m_next(next), m_handler(hander) {}
					
					connect_op(basic_connection& connection, next_type next,
							streambuf_ptr request, Handler& hander)
						: m_connection(connection), m_next(next)
						, m_handler(hander), m_request(request) {}
					
					connect_op(const connect_op& rhs)
						: m_connection(rhs.m_connection), m_next(rhs.m_next)
						, m_handler(rhs.m_handler), m_request(rhs.m_request) {}
					
		connect_op&	operator=(const connect_op& rhs);	

		void		operator()(const boost::system::error_code& ec)
					{
						if (ec)
							m_handler(ec);
						else
							(m_connection.*m_next)(m_handler);
					}
		
		void		operator()(const boost::system::error_code& ec, std::size_t bytes_transferred)
					{
						if (ec)
							m_handler(ec);
						else
							(m_connection.*m_next)(m_handler);
					}
		
		basic_connection&	m_connection;
		Handler				m_handler;
		next_type			m_next;
		streambuf_ptr		m_request;
	};

	template<typename Handler>
	void			async_connect(const std::string& user, Handler& handler)
					{
					    BOOST_ASIO_CONNECT_HANDLER_CHECK(ConnectHandler, handler) type_check;

						m_connected = m_authenticated = false;
						m_auth_state = auth_state_none;
						m_password_attempts = 0;
						m_in_seq_nr = m_out_seq_nr = m_packet_length = 0;
						
						streambuf_ptr request(new boost::asio::streambuf);
						ostream out(request.get());
						out << "SSH-2.0-libassh\r\n";
						
						boost::asio::async_write(m_socket, *request,
							connect_op<Handler>(*this, &basic_connection::handle_protocol_version_exchange_request,
								request, handler));
					}

	template<typename Handler>
	void			handle_protocol_version_exchange_request(Handler& handler)
					{
						boost::asio::async_read_until(m_socket, m_response, "\n",
							connect_op<Handler>(*this, &basic_connection::handle_protocol_version_exchange_response,
								handler));
					}

	template<typename Handler>
	void			handle_protocol_version_exchange_response(Handler& handler)
					{
						std::istream response_stream(&m_response);
						std::getline(response_stream, m_host_version);
						boost::algorithm::trim_right(m_host_version);
						
						if (not boost::algorithm::starts_with(m_host_version, "SSH-2.0"))
							handler(error::make_error_code(error::protocol_version_not_supported));

						// for now						
						handler(boost::system::error_code());
					}

	enum auth_state
	{
		auth_state_none,
		public_key,
		keyboard_interactive,
		password
	};

	socket_type&			m_socket;
	bool					m_connected;
	bool					m_authenticated;
	auth_state				m_auth_state;
	uint32					m_password_attempts;
	uint32					m_in_seq_nr, m_out_seq_nr;
	uint32					m_packet_length;
	boost::asio::streambuf	m_response;
	
	std::string				m_host_version;
};

typedef basic_connection<boost::asio::ip::tcp::socket> connection;
	
}
