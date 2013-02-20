//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include <assh/packet.hpp>

namespace assh
{

class key_exchange;
class channel;
	
extern const std::string kSSHVersionString;

class basic_connection
{
  public:
	virtual			~basic_connection();

	template<typename Handler>
	void			async_connect(const std::string& user, Handler&& handler)
					{
					    BOOST_ASIO_CONNECT_HANDLER_CHECK(ConnectHandler, handler) type_check;
				    	start_handshake(new connect_handler<Handler>(std::move(handler)));
					}

	void			open_channel(channel* ch, uint32 id);
	void			close_channel(channel* ch, uint32 id);

  protected:

					basic_connection(boost::asio::io_service& io_service, const std::string& user);

	struct basic_connect_handler
	{
		virtual				~basic_connect_handler() {}
		virtual void		handle_connect(const boost::system::error_code& ec, boost::asio::io_service& io_service) = 0;
	};

	template<class Handler>
	struct connect_handler : public basic_connect_handler
	{
							connect_handler(Handler&& handler) : m_handler(std::move(handler)) {}
							connect_handler(connect_handler&& rhs) : m_handler(std::move(rhs.m_handler)), m_ec(rhs.m_ec) {}
							connect_handler(connect_handler&& rhs, const boost::system::error_code& ec) : m_handler(std::move(rhs.m_handler)), m_ec(ec) {}
							connect_handler(const connect_handler& rhs) : m_handler(rhs.m_handler), m_ec(rhs.m_ec) {}
		connect_handler&	operator=(const connect_handler&);
		
		virtual void		handle_connect(const boost::system::error_code& ec, boost::asio::io_service& io_service)
							{
								io_service.post(connect_handler(std::move(m_handler), ec));
							}
		
		void				operator()()
							{
								m_handler(m_ec);
							}
		
		Handler						m_handler;
		boost::system::error_code	m_ec;
	};



	void			start_handshake(basic_connect_handler* handler);
	void			handle_protocol_version_request(const boost::system::error_code& ec, std::size_t);
	void			handle_protocol_version_response(const boost::system::error_code& ec, std::size_t);
	
	void			received_data(const boost::system::error_code& ec);

	void			process_packet(ipacket& in);
	void			process_kexinit(ipacket& in, opacket& out, boost::system::error_code& ec);
	void			process_kexdhreply(ipacket& in, opacket& out, boost::system::error_code& ec);
	void			process_newkeys(ipacket& in, opacket& out, boost::system::error_code& ec);
	void			process_service_accept(ipacket& in, opacket& out, boost::system::error_code& ec);
	void			process_userauth_success(ipacket& in, opacket& out, boost::system::error_code& ec);
	void			process_userauth_failure(ipacket& in, opacket& out, boost::system::error_code& ec);
	void			process_userauth_banner(ipacket& in, opacket& out, boost::system::error_code& ec);
	void			process_userauth_info_request(ipacket& in, opacket& out, boost::system::error_code& ec);

	void			process_channel(ipacket& in, opacket& out, boost::system::error_code& ec);

	void			full_stop(const boost::system::error_code& ec);

	virtual void	process_open_channel(const std::string& type, uint32 channel_id,
						opacket& out, boost::system::error_code& ec);

	template<class Handler>
	struct bound_handler
	{
		bound_handler(Handler handler, const boost::system::error_code& ec, ipacket&& packet)
			: m_handler(handler), m_ec(ec), m_packet(std::move(packet)) {}

		bound_handler(bound_handler&& rhs)
			: m_handler(std::move(rhs.m_handler)), m_ec(rhs.m_ec), m_packet(std::move(rhs.m_packet)) {}

		virtual void operator()()		{ m_handler(m_ec, m_packet); }
		
		Handler							m_handler;
		const boost::system::error_code	m_ec;
		ipacket							m_packet;
	};

	struct basic_read_handler
	{
		virtual			~basic_read_handler() {}
		virtual void	receive_and_post(ipacket&& p, boost::asio::io_service& io_service) = 0;
	};

	template<typename Handler>
	struct read_handler : public basic_read_handler
	{
						read_handler(Handler&& handler)
							: m_handler(std::move(handler)) {}
		
		virtual void	receive_and_post(ipacket&& p, boost::asio::io_service& io_service)
						{
							io_service.post(bound_handler<Handler>(m_handler, boost::system::error_code(), std::move(p)));
						}

		Handler		m_handler;
	};

	template<typename Handler>
	void			async_read_packet(Handler&& handler)
					{
						typedef read_handler<Handler> handler_type;
						
						if (not m_socket.is_open())
							m_socket.get_io_service().post(bound_handler<Handler>(handler, error::connection_lost, ipacket()));
						else
							m_read_handlers.push_back(new handler_type(std::move(handler)));
					}

	struct basic_write_op
	{
		virtual			~basic_write_op() {}
		virtual void	operator()(const boost::system::error_code& ec, std::size_t bytes_transferred) = 0;
	};

	template<typename Handler>
	struct write_op : public basic_write_op
	{
						write_op(Handler&& hander)
							: m_handler(std::move(hander)) {}
						
						write_op(const write_op& rhs)
							: m_handler(rhs.m_handler) {}
						
						write_op(write_op&& rhs)
							: m_handler(std::move(rhs.m_handler)) {}
					
		write_op&		operator=(const write_op& rhs);

		virtual void	operator()(const boost::system::error_code& ec, std::size_t bytes_transferred)
						{
							m_handler(ec, bytes_transferred);
						}
		
		Handler			m_handler;
	};

	template<typename Handler>
	void			async_write(boost::asio::streambuf* request, Handler&& handler)
					{
						async_write_int(request, new write_op<Handler>(std::move(handler)));
					}

	template<typename Handler>
	void			async_write(const opacket& p, Handler&& handler)
					{
						async_write_packet_int(p, new write_op<Handler>(std::move(handler)));
					}

	void			async_write_packet_int(const opacket& p, basic_write_op* handler);
	virtual void	async_write_int(boost::asio::streambuf* request, basic_write_op* handler) = 0;
	
	virtual void	async_read_version_string() = 0;
	virtual void	async_read(uint32 at_least) = 0;
	
	enum auth_state
	{
		auth_state_none,
		auth_state_public_key,
		auth_state_keyboard_interactive,
		auth_state_password
	};

	boost::asio::io_service&	m_io_service;
	std::string					m_user;
	basic_connect_handler*		m_connect_handler;
	bool						m_authenticated;
	std::string					m_host_version;
	std::vector<uint8>			m_my_payload, m_host_payload, m_session_id;
	auth_state					m_auth_state;
	uint32						m_password_attempts;
	uint32						m_in_seq_nr, m_out_seq_nr;
	ipacket						m_packet;
	uint32						m_iblocksize, m_oblocksize;
	boost::asio::streambuf		m_response;
	
	key_exchange*				m_key_exchange;
	std::unique_ptr<CryptoPP::StreamTransformation>			m_decryptor;
	std::unique_ptr<CryptoPP::StreamTransformation>			m_encryptor;
	std::unique_ptr<CryptoPP::MessageAuthenticationCode>	m_signer;
	std::unique_ptr<CryptoPP::MessageAuthenticationCode>	m_verifier;
	//std::unique_ptr<MSshPacketCompressor>					m_compressor;
	//std::unique_ptr<MSshPacketDecompressor>				m_decompressor;

	std::deque<basic_read_handler*>
								m_read_handlers;
	std::deque<opacket>			m_private_keys;

	std::list<channel*>			m_channels;

  private:
								basic_connection(const basic_connection&);
	basic_connection&			operator=(const basic_connection&);
};

template<typename SOCKET>
class basic_connection_t : public basic_connection
{
  public:
	typedef SOCKET		socket_type;

						basic_connection_t(socket_type& socket, const std::string& user)
							: basic_connection(socket.get_io_service(), user), m_socket(socket) {}

  protected:
	virtual void		async_write_int(boost::asio::streambuf* request, basic_write_op* op)
						{
							boost::asio::async_write(m_socket, *request,
								[op, request](const boost::system::error_code& ec, size_t bytes_transferred)
								{
									delete request;
									(*op)(ec, bytes_transferred);
									delete op;
								});
						}

	virtual void		async_read_version_string()
						{
							boost::asio::async_read_until(m_socket, m_response, "\n",
								[this](const boost::system::error_code& ec, size_t bytes_transferred)
							{
								handle_protocol_version_response(ec, bytes_transferred);
							});
						}
						
	virtual void		async_read(uint32 at_least)
						{
							boost::asio::async_read(m_socket, m_response, boost::asio::transfer_at_least(at_least),
								[this](const boost::system::error_code& ec, size_t bytes_transferred)
								{
									this->received_data(ec);
								});
						}

  private:
	socket_type&		m_socket;
};

typedef basic_connection_t<boost::asio::ip::tcp::socket> connection;

}

