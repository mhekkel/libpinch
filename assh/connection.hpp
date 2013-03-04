//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include <assh/config.hpp>

#include <list>

#include <boost/function.hpp>

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

	// configure before connecting
	void			set_algorithm(algorithm alg, direction dir, const std::string& preferred);

	// callbacks to be installed by owning object

	// bool validate_host_key(host, alg, key)
	typedef boost::function<bool(const std::string&,const std::string&,const std::vector<uint8>&)>
					validate_callback_type;

	// void request_password()
	typedef boost::function<void()> password_callback_type;

	virtual void	set_validate_callback(const validate_callback_type& cb);
	void			set_password_callback(const password_callback_type& cb);
	
	template<typename Handler>
	void			async_connect(Handler&& handler)
					{
					    BOOST_ASIO_CONNECT_HANDLER_CHECK(ConnectHandler, handler) type_check;
					    m_connect_handlers.push_back(new connect_handler<Handler>(std::move(handler)));
				    	start_handshake();
					}
	
	// to be called when requested by the connection object
	void			password(const std::string& pw);

	virtual void	disconnect();

	void			open_channel(channel* ch, uint32 id);
	void			close_channel(channel* ch, uint32 id);

	void			async_write(opacket&& p)
					{
						async_write(std::move(p), [](const boost::system::error_code&, std::size_t) {});
					}

	template<typename Handler>
	void			async_write(opacket&& p, Handler&& handler)
					{
						async_write_packet_int(std::move(p), new write_op<Handler>(std::move(handler)));
					}
	
	void			forward_agent(bool forward);

	virtual boost::asio::io_service&
					get_io_service() = 0;
	
	virtual bool	is_connected() const									{ return m_authenticated; }
	
	std::string		get_connection_parameters(direction d) const;
	std::string		get_key_exchange_algoritm() const;
	
	static void		close_for_disappeared_private_key(const std::vector<uint8>& hash);
	
  protected:

					basic_connection(boost::asio::io_service& io_service, const std::string& user);

	void			handle_connect_result(const boost::system::error_code& ec);

	struct basic_connect_handler
	{
		virtual				~basic_connect_handler() {}
		virtual void		handle_connect(const boost::system::error_code& ec, boost::asio::io_service& io_service) = 0;
	};
	
	typedef std::list<basic_connect_handler*>	connect_handler_list;

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


	virtual bool	validate_host_key(const std::string& pk_alg, const std::vector<uint8>& host_key) = 0;

	virtual void	start_handshake();
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

	void			process_channel_open(ipacket& in, opacket& out);
	void			process_channel(ipacket& in, opacket& out, boost::system::error_code& ec);

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

		Handler			m_handler;
	};

	template<typename Handler>
	void			async_read_packet(Handler&& handler)
					{
						typedef read_handler<Handler> handler_type;
						
//						if (not is_open())
//							m_socket.get_io_service().post(bound_handler<Handler>(handler, error::connection_lost, ipacket()));
//						else
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

	void			async_write_packet_int(opacket&& p, basic_write_op* handler);
	virtual void	async_write_int(boost::asio::streambuf* request, basic_write_op* handler) = 0;
	
	virtual void	async_read_version_string() = 0;
	virtual void	async_read(uint32 at_least) = 0;
	
	void			poll_channels();
	
	enum auth_state
	{
		auth_state_none,
		auth_state_connecting,
		auth_state_public_key,
		auth_state_keyboard_interactive,
		auth_state_password,
		auth_state_connected
	};

	boost::asio::io_service&	m_io_service;
	std::string					m_user;
	bool						m_authenticated;
	connect_handler_list		m_connect_handlers;
	std::string					m_host_version;
	std::vector<uint8>			m_my_payload, m_host_payload, m_session_id;
	auth_state					m_auth_state;
	uint32						m_password_attempts;
	std::vector<uint8>			m_private_key_hash;
	uint32						m_in_seq_nr, m_out_seq_nr;
	ipacket						m_packet;
	uint32						m_iblocksize, m_oblocksize;
	boost::asio::streambuf		m_response;

	validate_callback_type		m_validate_host_key_cb;
	password_callback_type		m_request_password_cb;
	
	key_exchange*				m_key_exchange;
	std::unique_ptr<CryptoPP::StreamTransformation>			m_decryptor;
	std::unique_ptr<CryptoPP::StreamTransformation>			m_encryptor;
	std::unique_ptr<CryptoPP::MessageAuthenticationCode>	m_signer;
	std::unique_ptr<CryptoPP::MessageAuthenticationCode>	m_verifier;

	std::unique_ptr<compression_helper>						m_compressor;
	std::unique_ptr<compression_helper>						m_decompressor;
	bool						m_delay_compressor, m_delay_decompressor;

	std::deque<basic_read_handler*>
								m_read_handlers;
	std::deque<opacket>			m_private_keys;

	std::list<channel*>			m_channels;
	bool						m_forward_agent;

	std::string					m_alg_kex,
								m_alg_enc_c2s, m_alg_ver_c2s, m_alg_cmp_c2s,
								m_alg_enc_s2c, m_alg_ver_s2c, m_alg_cmp_s2c;

  private:
								basic_connection(const basic_connection&);
	basic_connection&			operator=(const basic_connection&);

	static basic_connection*	s_first;
	basic_connection*			m_next;
};

// --------------------------------------------------------------------

class connection : public basic_connection
{
  public:
					connection(boost::asio::io_service& io_service,
						const std::string& user, const std::string& host, uint16 port);

	boost::asio::io_service&
					get_io_service() 		{ return m_socket.get_io_service(); }

	virtual void	disconnect();
	virtual bool	is_connected() const	{ return m_socket.is_open() and basic_connection::is_connected(); }

  protected:

	virtual void	start_handshake();

	virtual bool	validate_host_key(const std::string& pk_alg, const std::vector<uint8>& host_key);

	void			handle_resolve(const boost::system::error_code& err, boost::asio::ip::tcp::resolver::iterator endpoint_iterator);
	void			handle_connect(const boost::system::error_code& err, boost::asio::ip::tcp::resolver::iterator endpoint_iterator);
	
	virtual void	async_write_int(boost::asio::streambuf* request, basic_write_op* op);
	virtual void	async_read_version_string();
	virtual void	async_read(uint32 at_least);

  private:
	boost::asio::ip::tcp::socket	m_socket;
	boost::asio::ip::tcp::resolver	m_resolver;
	std::string						m_host;
	uint16							m_port;
};

}

