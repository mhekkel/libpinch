//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include <iostream>

#include <boost/asio.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/random/random_device.hpp>
#include <boost/random/uniform_int_distribution.hpp>
#include <boost/iostreams/filtering_stream.hpp>

#include <cryptopp/gfpcrypt.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/aes.h>
#include <cryptopp/des.h>
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>
#include <cryptopp/blowfish.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/factory.h>
#include <cryptopp/modes.h>

#include <assh/packet.hpp>
#include <assh/error.hpp>
#include <assh/hash.hpp>

namespace assh
{
	
using namespace CryptoPP;

extern const std::string kSSHVersionString;

class basic_connection
{
  public:
	typedef std::shared_ptr<boost::asio::streambuf>	streambuf_ptr;

					basic_connection(boost::asio::io_service& io_service)
						: m_io_service(io_service)
						, m_connect_handler(nullptr)
					{
					}

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
					    
					    if (m_connect_handler != nullptr)
					    	handler(error::make_error_code(error::protocol_error));
					    else
					    {
							m_authenticated = false;
							m_auth_state = auth_state_none;
							m_password_attempts = 0;
							m_in_seq_nr = m_out_seq_nr = 0;
							m_blocksize = 8;
							
							m_connect_handler = new connect_handler<Handler>(std::move(handler));
							
							static const std::string versionstring = kSSHVersionString + "\r\n";
							async_write(boost::asio::const_buffers_1(versionstring.c_str(), versionstring.length()),
								&basic_connection::handle_protocol_version_request);
					    }
					}

  protected:

	void			handle_protocol_version_request(const boost::system::error_code& ec);
	void			handle_protocol_version_response(const boost::system::error_code& ec);
	void			handle_kexinit_sent(const boost::system::error_code& ec);
	
	void			received_data(const boost::system::error_code& ec);

	void			process_packet(ipacket& in);
	opacket			process_kexinit(ipacket& in, boost::system::error_code& ec);
	opacket			process_kexdhreply(ipacket& in, boost::system::error_code& ec);
	opacket			process_newkeys(ipacket& in, boost::system::error_code& ec);

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
						
						if (not m_connected)
							m_socket.get_io_service().post(bound_handler<Handler>(handler, error::connection_lost, ipacket()));
						else
							m_read_handlers.push_back(new handler_type(std::move(handler)));
					}

	template<typename Handler>
	struct write_op
	{
					write_op(basic_connection& connection, Handler&& hander)
						: m_connection(connection), m_handler(std::move(hander)) {}
					
					write_op(basic_connection& connection, streambuf_ptr request, Handler&& hander)
						: m_connection(connection), m_handler(std::move(hander)), m_request(request) {}
					
					write_op(const write_op& rhs)
						: m_connection(rhs.m_connection), m_handler(rhs.m_handler), m_request(rhs.m_request) {}
					
					write_op(write_op&& rhs)
						: m_connection(std::move(rhs.m_connection))
						, m_handler(std::move(rhs.m_handler))
						, m_request(std::move(rhs.m_request)) {}
					
		write_op&	operator=(const write_op& rhs);	

		void		operator()(const boost::system::error_code& ec)
					{
						m_handler(ec);
					}

		void		operator()(const boost::system::error_code& ec, std::size_t bytes_transferred)
					{
						m_handler(ec);
					}
		
		basic_connection&	m_connection;
		Handler				m_handler;
		streambuf_ptr		m_request;
	};

	template<typename Handler>
	void			async_send_packet(const opacket& p, Handler&& handler)
					{
						streambuf_ptr request(new boost::asio::streambuf);
						std::ostream out(request.get());
						
//						io::filtering_stream<io::output> out;
						////if (m_compressor)
						////	out.push(*m_compressor);
						////if (m_encryptor_cipher)
						////	out.push(encrypt_op(m_out_seq_nr, m_encryptor_cipher, m_signer));
//						out.push(std::ostream(request.get()));
						
						p.write(out, m_blocksize);
						
						++m_out_seq_nr;
						boost::asio::async_write(m_socket, *request, write_op<Handler>(*this, request, std::move(handler)));
					}

	
	typedef void (basic_connection::*internal_handler_type)(const boost::system::error_code& ec);

	virtual void	async_write(const boost::asio::const_buffers_1& buffers, internal_handler_type) = 0;

	enum auth_state
	{
		auth_state_none,
		public_key,
		keyboard_interactive,
		password
	};

	boost::asio::io_service&	m_io_service;
	basic_connect_handler*	m_connect_handler;
	bool					m_connected;
	bool					m_authenticated;
	std::vector<uint8>		m_my_payload, m_host_payload, m_session_id;
	auth_state				m_auth_state;
	uint32					m_password_attempts;
	uint32					m_in_seq_nr, m_out_seq_nr;
	ipacket					m_packet;
	uint32					m_blocksize;
	boost::asio::streambuf	m_response;
	
	std::vector<std::string>
							m_kex_alg, m_server_host_key_alg,
							m_encryption_alg_c2s, m_encryption_alg_s2c,
							m_MAC_alg_c2s, m_MAC_alg_s2c,
							m_compression_alg_c2s, m_compression_alg_s2c,
							m_lang_c2s, m_lang_s2c;

	std::unique_ptr<BlockCipher>					m_decryptor_cipher;
	std::unique_ptr<StreamTransformation>			m_decryptor;
	std::unique_ptr<BlockCipher>					m_encryptor_cipher;
	std::unique_ptr<StreamTransformation>			m_encryptor;
	std::unique_ptr<MessageAuthenticationCode>		m_signer;
	std::unique_ptr<MessageAuthenticationCode>		m_verifier;
	//std::unique_ptr<MSshPacketCompressor>					m_compressor;
	//std::unique_ptr<MSshPacketDecompressor>					m_decompressor;

	Integer		m_x, m_e;
	std::vector<uint8>		m_keys[6];
	
	std::deque<basic_read_handler*>
							m_read_handlers;
	
	std::string				m_host_version;
	boost::random::random_device
							m_rng;
};

template<typename SOCKET>
class basic_connection_t : public basic_connection
{
  public:
							basic_connection_t(SOCKET& socket)
								: basic_connection(socket.get_io_service())
								, m_socket(socket)
							{
							}

  protected:

	virtual void	async_write(const boost::asio::const_buffers_1& buffers, internal_handler_type handler)
					{
						boost::asio::async_write(m_socket, buffers, boost::bind(handler, this, boost::asio::placeholders::error));
					}
	
	SOCKET&			m_socket;		
};

typedef basic_connection_t<boost::asio::ip::tcp::socket> connection;
	
}
