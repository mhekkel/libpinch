//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

//#include <iostream>
//
//#include <boost/asio.hpp>
//#include <boost/algorithm/string.hpp>
#include <boost/random/random_device.hpp>
//#include <boost/random/uniform_int_distribution.hpp>
//#include <boost/iostreams/filtering_stream.hpp>
//
//#include <cryptopp/gfpcrypt.h>
//#include <cryptopp/rsa.h>
//#include <cryptopp/osrng.h>
//#include <cryptopp/aes.h>
//#include <cryptopp/des.h>
//#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
//#include <cryptopp/md5.h>
//#include <cryptopp/blowfish.h>
//#include <cryptopp/filters.h>
//#include <cryptopp/files.h>
//#include <cryptopp/factory.h>
//#include <cryptopp/modes.h>

#include <assh/packet.hpp>
#include <assh/error.hpp>
#include <assh/hash.hpp>

namespace assh
{

extern const std::string kSSHVersionString;

template<typename SOCKET>
class basic_connection
{
  public:
	typedef SOCKET									socket_type;
	typedef std::shared_ptr<boost::asio::streambuf>	streambuf_ptr;

					basic_connection(socket_type& socket);
	virtual			~basic_connection();

	struct basic_connect_handler
	{
		virtual void		handle_connect(const boost::system::error_code& ec) = 0;
	};

	template<class Handler>
	struct connect_handler : public basic_connect_handler
	{
							connect_handler(Handler&& handler) : m_handler(std::move(handler)) {}
							connect_handler(connect_handler&& rhs) : m_handler(std::move(rhs.m_handler)) {}
							connect_handler(const connect_handler&);
		connect_handler&	operator=(const connect_handler&);
		
		virtual void		handle_connect(const boost::system::error_code& ec)		{ m_handler(ec); }
		
		Handler				m_handler;
	};

	template<typename Handler>
	void			async_connect(const std::string& user, Handler&& handler)
					{
					    BOOST_ASIO_CONNECT_HANDLER_CHECK(ConnectHandler, handler) type_check;
				    	start_handshake(new connect_handler<Handler>(move(handler)));
					}

  protected:

	void			start_handshake(basic_connect_handler* handler);
	void			handle_protocol_version_request(const boost::system::error_code& ec, streambuf_ptr);
	void			handle_protocol_version_response(const boost::system::error_code& ec);
	
	void			received_data(const boost::system::error_code& ec);

	void			process_packet(ipacket& in);
	opacket			process_kexinit(ipacket& in, boost::system::error_code& ec);
	opacket			process_kexdhreply(ipacket& in, boost::system::error_code& ec);
	opacket			process_newkeys(ipacket& in, boost::system::error_code& ec);
	opacket			process_userauth_success(ipacket& in, boost::system::error_code& ec);
	opacket			process_userauth_failure(ipacket& in, boost::system::error_code& ec);
	opacket			process_userauth_banner(ipacket& in, boost::system::error_code& ec);

	void			full_stop(const boost::system::error_code& ec);

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
		virtual void receive_and_post(ipacket&& p, boost::asio::io_service& io_service) = 0;
	};

	template<typename Handler>
	struct read_handler : public basic_read_handler
	{
		read_handler(Handler&& handler)
			: m_handler(std::move(handler)) {}
		
		virtual void receive_and_post(ipacket&& p, boost::asio::io_service& io_service)
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
//		virtual void operator()(const boost::system::error_code& ec) = 0;
		virtual void operator()(const boost::system::error_code& ec, std::size_t bytes_transferred) = 0;
	};

	template<typename Handler>
	struct write_op : public basic_write_op
	{
						write_op(Handler&& hander)
							: m_handler(std::move(hander)) {}
						
						write_op(streambuf_ptr request, Handler&& hander)
							: m_handler(std::move(hander)), m_request(request) {}
						
						write_op(const write_op& rhs)
							: m_handler(rhs.m_handler), m_request(rhs.m_request) {}
						
						write_op(write_op&& rhs)
							: m_handler(std::move(rhs.m_handler))
							, m_request(std::move(rhs.m_request)) {}
					
		write_op&		operator=(const write_op& rhs);

//		void		operator()(const boost::system::error_code& ec)
//					{
//						m_handler(ec);
//					}

		virtual void	operator()(const boost::system::error_code& ec, std::size_t bytes_transferred)
						{
							m_handler(ec);
						}
		
		Handler			m_handler;
		streambuf_ptr	m_request;
	};

	template<typename Handler>
	void			async_send_packet(const opacket& p, Handler&& handler)
					{
						async_send_packet_int(p, new write_op<Handler>(std::move(handler)));
					}

	void			async_send_packet_int(const opacket& p, basic_write_op* handler);
	
	enum auth_state
	{
		auth_state_none,
		public_key,
		keyboard_interactive,
		password
	};

	socket_type&				m_socket;
	basic_connect_handler*		m_connect_handler;
	bool						m_authenticated;
	std::vector<uint8>			m_my_payload, m_host_payload, m_session_id;
	auth_state					m_auth_state;
	uint32						m_password_attempts;
	uint32						m_in_seq_nr, m_out_seq_nr;
	ipacket						m_packet;
	uint32						m_blocksize;
	boost::asio::streambuf		m_response;
	
	std::vector<std::string>	m_kex_alg, m_server_host_key_alg,
								m_encryption_alg_c2s, m_encryption_alg_s2c,
								m_MAC_alg_c2s, m_MAC_alg_s2c,
								m_compression_alg_c2s, m_compression_alg_s2c,
								m_lang_c2s, m_lang_s2c;


	boost::random::random_device							m_rng;
	std::unique_ptr<CryptoPP::BlockCipher>					m_decryptor_cipher;
	std::unique_ptr<CryptoPP::StreamTransformation>			m_decryptor;
	std::unique_ptr<CryptoPP::BlockCipher>					m_encryptor_cipher;
	std::unique_ptr<CryptoPP::StreamTransformation>			m_encryptor;
	std::unique_ptr<CryptoPP::MessageAuthenticationCode>	m_signer;
	std::unique_ptr<CryptoPP::MessageAuthenticationCode>	m_verifier;
	//std::unique_ptr<MSshPacketCompressor>					m_compressor;
	//std::unique_ptr<MSshPacketDecompressor>				m_decompressor;

	CryptoPP::Integer			m_x, m_e;
	std::vector<uint8>			m_keys[6];
	
	std::deque<basic_read_handler*>
								m_read_handlers;
	std::string					m_host_version;
	
	

  private:
								basic_connection(const basic_connection&);
	basic_connection&			operator=(const basic_connection&);
};

typedef basic_connection<boost::asio::ip::tcp::socket> connection;
	
}

#include <assh/../src/connection.inl>

