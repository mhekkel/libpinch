//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include <assh/config.hpp>
#include <assh/error.hpp>
#include <assh/key_exchange.hpp>

#include <boost/algorithm/string.hpp>
#include <boost/iostreams/filtering_stream.hpp>
// #include <boost/iostreams/flush.hpp>

#include <list>
#include <functional>

#include <assh/packet.hpp>

namespace assh
{

class socket_closed_exception : public exception
{
  public:
	socket_closed_exception() : exception("socket is closed") {}
};

// --------------------------------------------------------------------
// Supported protocols

extern const std::string
	kKeyExchangeAlgorithms,
	kServerHostKeyAlgorithms,
	kEncryptionAlgorithms,
	kMacAlgorithms,
	kCompressionAlgorithms;

class key_exchange;
class channel;
typedef std::shared_ptr<channel> channel_ptr;
class port_forward_listener;

// --------------------------------------------------------------------

extern const std::string kSSHVersionString;

class basic_connection : public std::enable_shared_from_this<basic_connection>
{
  protected:
	virtual ~basic_connection();

  public:
	using executor_type = boost::asio::io_context::executor_type;

	basic_connection(const basic_connection &) = delete;
	basic_connection &operator=(const basic_connection &) = delete;

	// configure before connecting
	void set_algorithm(algorithm alg, direction dir, const std::string &preferred);

	// callbacks to be installed by owning object

	// bool validate_host_key(host, alg, key)
	typedef std::function<bool(const std::string &, const std::string &, const std::vector<uint8_t> &)>
		validate_callback_type;

	// void request_password()
	typedef std::function<void()> password_callback_type;

	// keyboard interactive support
	struct prompt
	{
		std::string str;
		bool echo;
	};
	typedef std::function<void(const std::string &, const std::string &, const std::vector<prompt> &)> keyboard_interactive_callback_type;

	virtual void set_validate_callback(const validate_callback_type &cb);
	void set_password_callback(const password_callback_type &cb);
	void set_keyboard_interactive_callback(const keyboard_interactive_callback_type &cb);

	template <typename Handler>
	void async_connect(Handler &&handler, channel_ptr opening_channel)
	{
		// BOOST_ASIO_CONNECT_HANDLER_CHECK(ConnectHandler, handler) type_check;
		m_connect_handlers.push_back(new connect_handler<Handler>(std::move(handler), opening_channel));
		start_handshake();
	}

	// template<typename CompletionToken>
	// auto async_connect2(std::shared_ptr<channel> opening_channel, CompletionToken&& token)
	// {
	// 	enum { connecting, handshaking };

	// 	return boost::asio::async_compose<CompletionToken, void(boost::system::error_code)>(
	// 		[
	// 			connection = shared_from_this(),
	// 			opening_channel,
	// 			state = connecting
	// 		]
	// 		(auto& self, const boost::system::error_code& ec = {}, std::size_t n = 0)
	// 		{
	// 			if (not ec)
	// 			{
	// 				switch (state)
	// 				{
	// 					case connecting:
	// 						if (not connection->is_socket_open())
	// 						{
	// 							connection->async_open_socket(std::move(self));
	// 							return;
	// 						}
	// 						// fall through
						
	// 					case handshaking:
	// 						break;
	// 				}
	// 			}

	// 			self.complete(ec);
	// 		}
	// 	);
	// }

	// template<typename Handler>
	// auto async_open_socket(Handler&& handler)
	// {
	// 	return boost::asio::async_initiate<Handler, void (boost::system::error_code)>(
	// 		initiate_async_open_socket(this), handler);
	// }

	// class initiate_async_open_socket
	// {
	//   public:
	// 	explicit initiate_async_open_socket(basic_connection* conn)
	// 		: self(conn)
	// 	{
	// 	}

	// 	executor_type get_executor() const noexcept
	// 	{
	// 		return self->get_executor();
	// 	}

	// 	template <typename WaitHandler>
	// 	void operator()(WaitHandler&& handler) const
	// 	{
	// 		WaitHandler handler2(std::move(handler));
	// 		self_->impl_.get_service().async_wait(
	// 			self_->impl_.get_implementation(), handler2.value,
	// 			self_->impl_.get_implementation_executor());
	// 	}
	//   private:
	// 	basic_connection* self;
	// };

	// to be called when requested by the connection object
	void password(const std::string &pw);
	void response(const std::vector<std::string> &responses);

	virtual void disconnect();
	virtual void rekey();

	void open_channel(channel_ptr ch, uint32_t id);
	void close_channel(channel_ptr ch, uint32_t id);

	bool has_open_channels();

	void async_write(opacket &&p)
	{
		auto self(shared_from_this());
		async_write(std::move(p), [self](const boost::system::error_code &ec, std::size_t) {
			if (ec)
				self->handle_error(ec);
		});
	}

	template <typename Handler>
	void async_write(opacket &&p, Handler &&handler)
	{
		async_write_packet_int(std::move(p), new write_op<Handler>(std::move(handler)));
	}

	virtual void handle_error(const boost::system::error_code &ec);

	void forward_agent(bool forward);
	void forward_port(const std::string &local_address, int16_t local_port,
						const std::string &remote_address, int16_t remote_port);
	void forward_socks5(const std::string &local_address, int16_t local_port);

	virtual boost::asio::io_service& get_io_service() = 0;
	virtual executor_type get_executor() const noexcept = 0;

	virtual bool is_connected() const	{ return m_authenticated; }
	virtual bool is_socket_open() const = 0;
	void keep_alive();

	std::string get_connection_parameters(direction d) const;
	std::string get_key_exchange_algoritm() const;
	std::vector<uint8_t>
	get_used_private_key() const { return m_private_key_hash; }

	virtual std::shared_ptr<basic_connection> get_proxy() const { return {}; }

  protected:
	basic_connection(boost::asio::io_service &io_service, const std::string &user);

	void reset();

	void handle_connect_result(const boost::system::error_code &ec);

	struct basic_connect_handler
	{
		basic_connect_handler(channel_ptr opening_channel) : m_opening_channel(opening_channel) {}
		virtual ~basic_connect_handler() {}

		virtual void handle_connect(const boost::system::error_code &ec, boost::asio::io_service &io_service) = 0;
		void handle_banner(const std::string &message, const std::string &lang);

		//virtual void		handle_connect(const boost::system::error_code& ec) = 0;
		channel_ptr m_opening_channel;
	};

	typedef std::list<basic_connect_handler *> connect_handler_list;

	template <class Handler>
	struct connect_handler : public basic_connect_handler
	{
		connect_handler(Handler &&handler, channel_ptr opening_channel)
			: basic_connect_handler(opening_channel), m_handler(std::move(handler)) {}
		connect_handler(Handler &&handler, channel_ptr opening_channel, const boost::system::error_code &ec)
			: basic_connect_handler(opening_channel), m_handler(std::move(handler)), m_ec(ec) {}

		virtual void handle_connect(const boost::system::error_code &ec, boost::asio::io_service &io_service)
		{
			io_service.post(connect_handler(std::move(m_handler), std::move(m_opening_channel), ec));
		}

		void operator()()
		{
			m_handler(m_ec);
		}

		Handler m_handler;
		boost::system::error_code m_ec;
	};

	virtual bool validate_host_key(const std::string &pk_alg, const std::vector<uint8_t> &host_key) = 0;

	virtual void start_handshake();
	void handle_protocol_version_request(const boost::system::error_code &ec, std::size_t);
	void handle_protocol_version_response(const boost::system::error_code &ec, std::size_t);

	void received_data(const boost::system::error_code &ec);

	void process_packet(ipacket &in);
	void process_kexinit(ipacket &in, opacket &out, boost::system::error_code &ec);
	void process_kexdhreply(ipacket &in, opacket &out, boost::system::error_code &ec);
	void process_newkeys(ipacket &in, opacket &out, boost::system::error_code &ec);
	void process_service_accept(ipacket &in, opacket &out, boost::system::error_code &ec);
	void process_userauth_success(ipacket &in, opacket &out, boost::system::error_code &ec);
	void process_userauth_failure(ipacket &in, opacket &out, boost::system::error_code &ec);
	void process_userauth_banner(ipacket &in, opacket &out, boost::system::error_code &ec);
	void process_userauth_info_request(ipacket &in, opacket &out, boost::system::error_code &ec);

	void process_channel_open(ipacket &in, opacket &out);
	void process_channel(ipacket &in, opacket &out, boost::system::error_code &ec);

	template <class Handler>
	struct bound_handler
	{
		bound_handler(Handler handler, const boost::system::error_code &ec, ipacket &&packet)
			: m_handler(handler), m_ec(ec), m_packet(std::move(packet)) {}

		bound_handler(bound_handler &&rhs)
			: m_handler(std::move(rhs.m_handler)), m_ec(rhs.m_ec), m_packet(std::move(rhs.m_packet)) {}

		virtual void operator()() { m_handler(m_ec, m_packet); }

		Handler m_handler;
		const boost::system::error_code m_ec;
		ipacket m_packet;
	};

	struct basic_read_handler
	{
		virtual ~basic_read_handler() {}
		virtual void receive_and_post(ipacket &&p, boost::asio::io_service &io_service) = 0;
	};

	template <typename Handler>
	struct read_handler : public basic_read_handler
	{
		read_handler(Handler &&handler)
			: m_handler(std::move(handler)) {}

		virtual void receive_and_post(ipacket &&p, boost::asio::io_service &io_service)
		{
			io_service.post(bound_handler<Handler>(std::move(m_handler), boost::system::error_code(), std::move(p)));
		}

		Handler m_handler;
	};

	template <typename Handler>
	void async_read_packet(Handler &&handler)
	{
		typedef read_handler<Handler> handler_type;

		//						if (not is_open())
		//							m_socket.get_io_service().post(bound_handler<Handler>(handler, error::connection_lost, ipacket()));
		//						else
		m_read_handlers.push_back(new handler_type(std::move(handler)));
	}

	struct basic_write_op
	{
		virtual ~basic_write_op() {}
		virtual void operator()(const boost::system::error_code &ec, std::size_t bytes_transferred) = 0;
	};

	template <typename Handler>
	struct write_op : public basic_write_op
	{
		write_op(Handler &&hander)
			: m_handler(std::move(hander)) {}

		write_op(const write_op &rhs)
			: m_handler(rhs.m_handler) {}

		write_op(write_op &&rhs)
			: m_handler(std::move(rhs.m_handler)) {}

		write_op &operator=(const write_op &rhs);

		virtual void operator()(const boost::system::error_code &ec, std::size_t bytes_transferred)
		{
			m_handler(ec, bytes_transferred);
		}

		Handler m_handler;
	};

	template <typename Handler>
	void async_write(boost::asio::streambuf *request, Handler &&handler)
	{
		async_write_int(request, new write_op<Handler>(std::move(handler)));
	}

	void async_write_packet_int(opacket &&p, basic_write_op *handler);
	virtual void async_write_int(boost::asio::streambuf *request, basic_write_op *handler) = 0;

	virtual void async_read_version_string() = 0;
	virtual void async_read(uint32_t at_least) = 0;

	void poll_channels();

	enum auth_state
	{
		auth_state_none,
		auth_state_connecting,
		auth_state_public_key,
		auth_state_keyboard_interactive,
		auth_state_password,
		auth_state_connected
	};

	boost::asio::io_service &m_io_service;
	std::string m_user;
	bool m_authenticated;
	bool m_sent_kexinit;
	connect_handler_list m_connect_handlers;
	std::string m_host_version;
	std::vector<uint8_t> m_my_payload, m_host_payload, m_session_id;
	auth_state m_auth_state;
	int64_t m_last_io;
	uint32_t m_password_attempts;
	std::vector<uint8_t> m_private_key_hash;
	uint32_t m_in_seq_nr, m_out_seq_nr;
	ipacket m_packet;
	uint32_t m_iblocksize, m_oblocksize;
	boost::asio::streambuf m_response;

	validate_callback_type m_validate_host_key_cb;
	password_callback_type m_request_password_cb;
	keyboard_interactive_callback_type
		m_keyboard_interactive_cb;

	key_exchange *m_key_exchange;
	std::unique_ptr<CryptoPP::StreamTransformation> m_decryptor;
	std::unique_ptr<CryptoPP::StreamTransformation> m_encryptor;
	std::unique_ptr<CryptoPP::MessageAuthenticationCode> m_signer;
	std::unique_ptr<CryptoPP::MessageAuthenticationCode> m_verifier;

	std::unique_ptr<compression_helper> m_compressor;
	std::unique_ptr<compression_helper> m_decompressor;
	bool m_delay_compressor, m_delay_decompressor;

	std::deque<basic_read_handler *>
		m_read_handlers;
	std::deque<opacket> m_private_keys;

	std::list<channel_ptr> m_channels;
	bool m_forward_agent;
	port_forward_listener *m_port_forwarder;

	std::string m_alg_kex,
		m_alg_enc_c2s, m_alg_ver_c2s, m_alg_cmp_c2s,
		m_alg_enc_s2c, m_alg_ver_s2c, m_alg_cmp_s2c;
};

// --------------------------------------------------------------------

class connection : public basic_connection
{
  public:
	using executor_type = basic_connection::executor_type;

	connection(boost::asio::io_service &io_service,
				const std::string &user, const std::string &host, int16_t port);

	boost::asio::io_service& get_io_service();
	
	executor_type get_executor() const noexcept
	{
		// return boost::asio::get_associated_executor(m_socket);
		return m_io_service.get_executor();
	}

	virtual void disconnect();
	virtual bool is_connected() const	{ return m_socket.is_open() and basic_connection::is_connected(); }
	virtual bool is_socket_open() const	{ return m_socket.is_open(); }

  protected:
	virtual void start_handshake();

	virtual bool validate_host_key(const std::string &pk_alg, const std::vector<uint8_t> &host_key);

	void handle_resolve(const boost::system::error_code &err, boost::asio::ip::tcp::resolver::iterator endpoint_iterator);
	void handle_connect(const boost::system::error_code &err, boost::asio::ip::tcp::resolver::iterator endpoint_iterator);

	virtual void async_write_int(boost::asio::streambuf *request, basic_write_op *op);
	virtual void async_read_version_string();
	virtual void async_read(uint32_t at_least);

  private:
	boost::asio::io_service& m_io_service;
	boost::asio::ip::tcp::socket m_socket;
	boost::asio::ip::tcp::resolver m_resolver;
	std::string m_host;
	int16_t m_port;
};

// --------------------------------------------------------------------

class connection2 : public std::enable_shared_from_this<connection2>
{
  public:

	connection2(const connection2&) = delete;
	connection2& operator=(const connection2&) = delete;

	connection2(boost::asio::io_context& io_context, const std::string &user, const std::string &host, int16_t port);

	template<typename CompletionToken>
	auto async_connect(CompletionToken&& token)
	{
		enum { starting, resolving, connecting };

		return boost::asio::async_compose<CompletionToken, void(boost::system::error_code)>(
			[
				this,
				conn = shared_from_this(),
				state = starting,
				next = boost::asio::ip::tcp::resolver::iterator{}
			]
			(auto& self, const boost::system::error_code ec = {}, boost::asio::ip::tcp::resolver::iterator endpoint_iterator = {}) mutable
			{
				switch (state)
				{
					case starting:
						if (not m_socket.is_open())
						{
							boost::asio::ip::tcp::resolver resolver(m_strand);
							boost::asio::ip::tcp::resolver::query query(m_host, std::to_string(m_port));

							state = resolving;

							m_resolver.async_resolve(query, std::move(self));
							return;
						}
						break;

					case resolving:
						if (not ec)
						{
							state = connecting;
							auto endpoint = *endpoint_iterator;
							next = ++endpoint_iterator;

							m_socket.async_connect(endpoint, std::move(self));
							return;
						}
						break;

					case connecting:
						if (ec and next != boost::asio::ip::tcp::resolver::iterator())
						{
							auto endpoint = *next;
							++next;

							m_socket.close();
							m_socket.async_connect(endpoint, std::move(self));
							return;
						}
						break;
				}

				self.complete(ec);
			}, token
		);
	}

	template<typename CompletionToken>
	auto async_authenticate(CompletionToken&& token)
	{
		


		if (not m_socket.is_open())
			throw socket_closed_exception();

		enum { starting, handshaking, read_version_string, rekeying, rekeying2, rekeying3, rekeying4, newkeys, done };

		auto request = std::shared_ptr<boost::asio::streambuf>(new boost::asio::streambuf);
		auto packet = std::shared_ptr<ipacket>(new ipacket);

		return boost::asio::async_compose<CompletionToken, void(boost::system::error_code)>(
			[
				this,
				state = starting,
				conn = shared_from_this(),
				request,
				packet
			]
			(auto& self, boost::system::error_code ec = {} , std::size_t n = 0) mutable
			{
				if (ec)
				{
					reset();
					self.complete(ec);
					return;
				}

				ipacket& in = *packet;
				opacket out;

				switch (state)
				{
					case starting:
					{
						state = handshaking;

						reset();
						m_auth_state = auth_state_connecting;

						std::ostream out(request.get());
						out << kSSHVersionString << "\r\n";

						boost::asio::async_write(m_socket, *request, std::move(self));
						return;
					}
					
					case handshaking:
						state = read_version_string;
						boost::asio::async_read_until(m_socket, *request, "\n", std::move(self));
						return;
					
					case read_version_string:
					{
						state = rekeying;

						std::istream response_stream(request.get());

						std::getline(response_stream, m_host_version);
						boost::algorithm::trim_right(m_host_version);

						if (m_host_version.compare(0, 7, "SSH-2.0") != 0)
						{
							ec = error::make_error_code(error::protocol_version_not_supported);
							break;
						}

						out = get_rekey_msg();
						async_write_packet(std::move(out), std::move(self));
						return;
					}

					case rekeying:
						state = rekeying2;
						async_read_packet(in, std::move(self));
						return;
					
					case rekeying2:
						if (packet->message() != msg_kexinit)
							ec = error::make_error_code(error::kex_error);
						else
						{
							process_kexinit(in, out, ec);
							if (not ec)
							{
								state = rekeying3;
								async_write_packet(std::move(out), std::move(self));
								return;
							}
						}
						break;

					case rekeying3:
						state = rekeying4;
						async_read_packet(in, std::move(self));
						return;

					case rekeying4:
						if (m_key_exchange->process(in, out, ec) and not ec)
						{
							if (not out.empty())
							{
								state = rekeying3;
								async_write_packet(std::move(out), std::move(self));
							}
							else
								async_read_packet(in, std::move(self));
						}
						else if ((message_type)in == msg_newkeys)
						{
							state = newkeys;
							process_newkeys(in, out, ec);
							if (not ec and out.empty())
								ec = error::make_error_code(error::kex_error);
							if (ec)
								break;
							async_write_packet(std::move(out), std::move(self));
						}
						else
						{
							ec = error::make_error_code(error::kex_error);
							break;
						}
						return;

					case newkeys:
					{
						ec = error::make_error_code(error::auth_cancelled_by_user);

						
						break;
					}

				}

				if (not ec and not out.empty())
					async_write_packet(std::move(out), std::move(self));
				else
					self.complete(ec);
			}, token
		);
	}

	template<typename CompletionToken>
	auto async_write_packet(opacket&& p, CompletionToken&& token)
	{
		namespace io = boost::iostreams;

		auto request = std::shared_ptr<boost::asio::streambuf>(new boost::asio::streambuf);

		enum { starting, sending };

		return boost::asio::async_compose<CompletionToken,void(boost::system::error_code)>(
			[
				this,
				conn = shared_from_this(),
				packet = std::move(p),
				request,
				state = starting
			]
			(auto& self, boost::system::error_code ec = {}, std::size_t n = 0) mutable
			{
				if (not ec and state == starting)
				{
					prepare(std::move(packet), *request, ec);

					if (not ec)
					{
						state = sending;
						boost::asio::async_write(m_socket, *request, std::move(self));
						return;
					}
				}

				self.complete(ec);
			}, token
		);
	}

	template<typename CompletionToken>
	auto async_read_packet(ipacket& p, CompletionToken&& token)
	{
		p.clear();

		return boost::asio::async_compose<CompletionToken,void(boost::system::error_code)>(
			[
				this,
				conn = shared_from_this(),
				&p
			]
			(auto& self, boost::system::error_code ec = {}, std::size_t n = 0) mutable
			{
				if (ec)
				{
					self.complete(ec);
					return;
				}

				auto at_least = receive_packet(p, m_response, ec);
				
				if (not ec and at_least > 0)
				{
					boost::asio::async_read(m_socket, m_response, boost::asio::transfer_at_least(m_iblocksize), std::move(self));
					return;
				}

				self.complete(ec);
			}, token
		);
	}

	void reset()
	{
		m_authenticated = false;
		m_auth_state = auth_state_none;
		m_private_key_hash.clear();
		delete m_key_exchange;
		m_key_exchange = nullptr;
		m_session_id.clear();
		m_packet.clear();
		m_encryptor.reset(nullptr);
		m_decryptor.reset(nullptr);
		m_signer.reset(nullptr);
		m_verifier.reset(nullptr);
		m_compressor.reset(nullptr);
		m_decompressor.reset(nullptr);
		m_delay_decompressor = m_delay_compressor = false;
		m_password_attempts = 0;
		m_in_seq_nr = m_out_seq_nr = 0;
		m_iblocksize = m_oblocksize = 8;
		m_last_io = 0;
	}

	void prepare(opacket&& packet, boost::asio::streambuf& buffer, boost::system::error_code& ec);

	std::size_t receive_packet(ipacket& p, boost::asio::streambuf& buffer, boost::system::error_code& ec);
	void process_kexinit(ipacket &in, opacket &out, boost::system::error_code &ec);
	void process_newkeys(ipacket &in, opacket &out, boost::system::error_code &ec);

  private:

	opacket get_rekey_msg();

	enum auth_state
	{
		auth_state_none,
		auth_state_connecting,
		auth_state_public_key,
		auth_state_keyboard_interactive,
		auth_state_password,
		auth_state_connected
	};

	boost::asio::strand<boost::asio::io_context::executor_type> m_strand;
	boost::asio::ip::tcp::socket m_socket;
	boost::asio::ip::tcp::resolver m_resolver;
	std::string m_host;
	int16_t m_port;
	std::string m_user;

	bool m_authenticated;
	bool m_sent_kexinit;
	std::string m_host_version;
	std::vector<uint8_t> m_my_payload, m_host_payload, m_session_id;
	auth_state m_auth_state;
	int64_t m_last_io;
	uint32_t m_password_attempts;
	std::vector<uint8_t> m_private_key_hash;
	uint32_t m_in_seq_nr, m_out_seq_nr;
	ipacket m_packet;
	uint32_t m_iblocksize, m_oblocksize;
	boost::asio::streambuf m_response;

	// validate_callback_type m_validate_host_key_cb;
	// password_callback_type m_request_password_cb;
	// keyboard_interactive_callback_type
	// 	m_keyboard_interactive_cb;

	key_exchange *m_key_exchange;
	std::unique_ptr<CryptoPP::StreamTransformation> m_decryptor;
	std::unique_ptr<CryptoPP::StreamTransformation> m_encryptor;
	std::unique_ptr<CryptoPP::MessageAuthenticationCode> m_signer;
	std::unique_ptr<CryptoPP::MessageAuthenticationCode> m_verifier;

	std::unique_ptr<compression_helper> m_compressor;
	std::unique_ptr<compression_helper> m_decompressor;
	bool m_delay_compressor, m_delay_decompressor;

	std::deque<opacket> m_private_keys;

	std::list<channel_ptr> m_channels;
	bool m_forward_agent;
	port_forward_listener *m_port_forwarder;

	std::string m_alg_kex,
		m_alg_enc_c2s, m_alg_ver_c2s, m_alg_cmp_c2s,
		m_alg_enc_s2c, m_alg_ver_s2c, m_alg_cmp_s2c;
};


} // namespace assh
