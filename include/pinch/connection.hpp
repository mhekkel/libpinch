//        Copyright Maarten L. Hekkelman 2013-2021
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

/// \file
/// definition of the connection classes

#include <chrono>
#include <deque>
#include <memory>
#include <pinch/crypto-engine.hpp>
#include <pinch/error.hpp>
#include <pinch/known_hosts.hpp>
#include <pinch/operations.hpp>
#include <pinch/pinch.hpp>
#include <pinch/ssh_agent.hpp>

namespace pinch
{

class channel;
using channel_ptr = std::shared_ptr<channel>;

// --------------------------------------------------------------------

class basic_connection;
class key_exchange;
class port_forward_listener;

// --------------------------------------------------------------------

/// \brief The SSH version string that will be communicated with the server
extern const std::string kSSHVersionString;

/// \brief The auth_state_type is used by the async_connect_impl to keep track
/// of its state
enum class auth_state_type
{
	none,
	public_key,
	keyboard_interactive,
	password,
	error
};

/// \brief keyboard interactive support
///
/// This is used in the credentials callback, the str field contains the string
/// to display to the user, the echo flag indicates wether the reply typed by
/// the user should be echo'd to the screen, or should be hidden using bullets
/// of asterisks e.g.
struct prompt
{
	std::string str;
	bool echo;
};

/// \brief The type of the callback to provide a single password
///
/// The result of this callback should be the password as string

using provide_password_callback_type = std::function<std::string()>;

/// \brief The type of the callback to provide credential information
///
/// The result of this callback should be the vector of requested values as strings.

using provide_credentials_callback_type =
	std::function<std::vector<std::string>(const std::string &name,
		const std::string &instruction, const std::string &lang,
		const std::vector<prompt> &prompts)>;

// --------------------------------------------------------------------

namespace detail
{

	/// \brief enum used in connection::async_wait
	enum class connection_wait_type
	{
		read,
		write
	};

	/// \brief internal class used for the handshake in setting up a connection
	struct async_connect_impl
	{
		enum class state_type
		{
			connect,
			start,
			wrote_version,
			reading,
			rekeying,
			authenticating
		};

		boost::asio::streambuf &response;
		std::shared_ptr<basic_connection> conn;
		std::string user;
		int m_password_attempts = 0;

		state_type state = state_type::connect;
		auth_state_type auth_state = auth_state_type::none;

		std::string host_version;
		std::unique_ptr<boost::asio::streambuf> request =
			std::make_unique<boost::asio::streambuf>();
		std::unique_ptr<ipacket> packet = std::make_unique<ipacket>();
		std::unique_ptr<key_exchange> kex;
		std::deque<opacket> private_keys;
		blob private_key_hash;

		template <typename Self>
		void operator()(Self &self, boost::system::error_code ec = {},
			std::size_t bytes_transferred = 0);

		template <typename Self>
		void failed(Self &self, boost::system::error_code ec);

		void process_userauth_failure(ipacket &in, opacket &out,
			boost::system::error_code &ec);
		void process_userauth_info_request(ipacket &in, opacket &out,
			boost::system::error_code &ec);
	};

	// --------------------------------------------------------------------

	class wait_connection_op : public operation
	{
	  public:
		boost::system::error_code m_ec;
		connection_wait_type m_type;
	};

	template <typename Handler, typename IoExecutor>
	class wait_connection_handler : public wait_connection_op
	{
	  public:
		wait_connection_handler(Handler &&h, const IoExecutor &io_ex,
			connection_wait_type type)
			: m_handler(std::forward<Handler>(h))
			, m_io_executor(io_ex)
			, m_work(m_handler, m_io_executor)
		{
			m_type = type;
		}

		virtual void complete(const boost::system::error_code &ec = {},
			std::size_t bytes_transferred = 0) override
		{
			binder<Handler, boost::system::error_code> handler(m_handler, m_ec);

			m_work.complete(handler, handler.m_handler);
		}

	  private:
		Handler m_handler;
		IoExecutor m_io_executor;
		handler_work<Handler, IoExecutor> m_work;
	};

} // namespace detail

// --------------------------------------------------------------------

class basic_connection : public std::enable_shared_from_this<basic_connection>
{
  public:
	basic_connection(const basic_connection &) = delete;
	basic_connection &operator=(const basic_connection &) = delete;

	/// The type of the lowest layer.
	using tcp_socket_type = boost::asio::ip::tcp::socket;
	using lowest_layer_type = typename tcp_socket_type::lowest_layer_type;

	/// The type of the executor associated with the object.
	using executor_type = typename lowest_layer_type::executor_type;

	virtual executor_type get_executor() noexcept = 0;
	virtual lowest_layer_type &lowest_layer() = 0;
	virtual const lowest_layer_type &lowest_layer() const = 0;

	virtual void open() = 0;
	virtual bool is_open() const = 0;

	using wait_type = detail::connection_wait_type;

	virtual ~basic_connection() {}

	virtual void disconnect();

	void rekey();

	template <typename Handler>
	auto async_wait(wait_type type, Handler &&handler)
	{
		return boost::asio::async_initiate<Handler,
			void(boost::system::error_code)>(
			async_wait_impl{}, handler, this, type);
	}

	template <typename Handler>
	auto async_write(opacket &&p, Handler &&handler)
	{
		return async_write(m_crypto_engine.get_next_request(std::move(p)),
			std::move(handler));
	}

	template <typename Handler>
	auto async_write(std::unique_ptr<boost::asio::streambuf> buffer,
		Handler &&handler)
	{
		enum
		{
			start,
			writing
		};

		return boost::asio::async_compose<Handler, void(boost::system::error_code,
													   std::size_t)>(
			[buffer = std::move(buffer), conn = this->shared_from_this(),
				state = start](auto &self, const boost::system::error_code &ec = {},
				std::size_t bytes_received = 0) mutable {
				if (not ec and state == start)
				{
					state = writing;
					boost::asio::async_write(*conn, *buffer, std::move(self));
					return;
				}

				self.complete(ec, 0);
			},
			handler, *this);
	}

	void async_write(opacket &&out)
	{
		async_write(std::move(out),
			[this](const boost::system::error_code &ec, std::size_t) {
				if (ec)
					this->handle_error(ec);
			});
	}

	void forward_agent(bool forward) { m_forward_agent = forward; }

	void keep_alive();

	void forward_port(const std::string &local_address, uint16_t local_port,
		const std::string &remote_address, uint16_t remote_port);

	void forward_socks5(const std::string &local_address, uint16_t local_port);

	std::string get_connection_parameters(direction dir) const
	{
		return m_crypto_engine.get_connection_parameters(dir);
	}

	std::string get_key_exchange_algorithm() const
	{
		return m_crypto_engine.get_key_exchange_algorithm();
	}

  private:
	void async_read()
	{
		boost::asio::async_read(
			*this, m_response, boost::asio::transfer_at_least(1),
			[self = this->shared_from_this()](const boost::system::error_code &ec,
				size_t bytes_transferred) {
				self->received_data(ec);
			});
	}

  public:
	/// \brief Returns true if the connection uses the public key \a pk_hash
	bool uses_private_key(const blob &pk_hash)
	{
		return m_private_key_hash == pk_hash;
	}

	/// \brief Return true if the connection should accept the host key \a key
	/// and algorithm \a algorithm when connecting to host \a host
	///
	/// This function delegates the question to known_hosts first which will in
	/// turn call the registered callback when needed. The reason for this route
	/// is to allow per-connection validation, making feedback to the user easier.

	bool accept_host_key(const std::string &algorithm, const blob &key)
	{
		return known_hosts::instance().accept_host_key(m_host, algorithm, key, m_accept_host_key_handler);
	}

	/// \brief register a function that will return whether a host key
	/// should be considered known.
	///
	/// The callback \a handler will be called in the boost::io_context thread.

	template <typename Handler>
	void set_accept_host_key_handler(Handler &&handler)
	{
		static_assert(std::is_assignable_v<accept_host_key_handler_type, decltype(handler)>, "Invalid handler");
		m_accept_host_key_handler = handler;
	}

	/// \brief register a function that will return whether a host key is valid, but from possibly another thread
	///
	/// The callback \a handler will be called using the executor, potentially running a separate thread.
	/// All I/O will be blocked in this thread until a reply is received.

	template <typename Handler, typename Executor>
	void set_accept_host_key_handler(Handler &&handler, Executor &executor)
	{
		static_assert(std::is_assignable_v<accept_host_key_handler_type, decltype(handler)>, "Invalid handler");

		m_accept_host_key_handler = [&executor, this, handler = std::move(handler)](const std::string &host_name, const std::string &algorithm, const pinch::blob &key, host_key_state state) {
			return async_accept_host_key(host_name, algorithm, key, state, handler, executor);
		};
	}

	std::string provide_password()
	{
		return m_provide_password_handler();
	}

	template <typename Handler>
	void set_provide_password_callback(Handler &&handler)
	{
		static_assert(std::is_assignable_v<provide_password_callback_type, decltype(handler)>, "Invalid handler");

		m_provide_password_handler = handler;
	}

	template <typename Handler, typename Executor>
	void set_provide_password_callback(Handler handler, Executor &executor)
	{
		static_assert(std::is_assignable_v<provide_password_callback_type, decltype(handler)>, "Invalid handler");

		m_provide_password_handler = [&executor, this, handler = std::move(handler)]() {
			return async_provide_password(handler, executor);
		};
	}

	std::vector<std::string> provide_credentials(const std::string &name,
		const std::string &instruction, const std::string &lang,
		const std::vector<prompt> &prompts)
	{
		return m_provide_credentials_handler(name, instruction, lang, prompts);
	}

	template <typename Handler>
	void set_provide_credentials_callback(Handler &&handler)
	{
		static_assert(std::is_assignable_v<provide_credentials_callback_type, decltype(handler)>, "Invalid handler");

		m_provide_credentials_handler = handler;
	}

	template <typename Handler, typename Executor>
	void set_provide_credentials_callback(Handler handler, Executor &executor)
	{
		static_assert(std::is_assignable_v<provide_credentials_callback_type, decltype(handler)>, "Invalid handler");

		m_provide_credentials_handler = [&executor, this, handler = std::move(handler)](const std::string &name,
											const std::string &instruction, const std::string &lang,
											const std::vector<prompt> &prompts) {
			return async_provide_credentials(name, instruction, lang, prompts, handler, executor);
		};
	}

	virtual bool is_connected() const { return m_auth_state == authenticated; }

	// callbacks to be installed by owning object
	friend struct detail::async_connect_impl;

	template <typename Handler>
	void async_connect(Handler &&handler, channel_ptr channel)
	{
		switch (m_auth_state)
		{
			case authenticated:
				assert(false);
				handler(error::make_error_code(error::protocol_error));
				break;

			case handshake:
				m_channels.push_back(channel);
				break;

			case none:
				m_auth_state = handshake;
				m_channels.push_back(channel);
				boost::asio::async_compose<Handler, void(boost::system::error_code)>(
					detail::async_connect_impl{m_response, this->shared_from_this(), m_user},
					handler, *this);
		}
	}

	virtual void handle_error(const boost::system::error_code &ec);
	void reset();

	void newkeys(key_exchange &kex, boost::system::error_code &ec)
	{
		m_crypto_engine.newkeys(kex, m_auth_state == authenticated);
	}

	void userauth_success(const std::string &host_version, const blob &session_id,
		const blob &pk_hash);

	void open_channel(channel_ptr ch, uint32_t id);
	void close_channel(channel_ptr ch, uint32_t id);

	bool has_open_channels();

	template <typename MutableBufferSequence, typename ReadHandler>
	auto async_read_some(const MutableBufferSequence &buffers,
		ReadHandler &&handler)
	{
		return boost::asio::async_initiate<
			ReadHandler, void(boost::system::error_code, std::size_t)>(
			async_read_impl{}, handler, this, buffers);
	}

	template <typename ConstBufferSequence, typename WriteHandler>
	auto async_write_some(const ConstBufferSequence &buffers,
		WriteHandler &&handler)
	{
		return boost::asio::async_initiate<
			WriteHandler, void(boost::system::error_code, std::size_t)>(
			async_write_impl{}, handler, this, buffers);
	}

  protected:
	basic_connection(const std::string &user, const std::string &host,
		uint16_t port)
		: m_user(user)
		, m_host(host)
		, m_port(port)
	{
	}

	bool receive_packet(ipacket &packet, boost::system::error_code &ec);

	void received_data(boost::system::error_code ec);

	void process_packet(ipacket &in);
	void process_channel_open(ipacket &in, opacket &out);
	void process_channel(ipacket &in, opacket &out,
		boost::system::error_code &ec);

	void handle_banner(const std::string &message, const std::string &lang);

	// --------------------------------------------------------------------

	/// \brief async accept_host_key support
	template <typename Handler, typename Executor>
	host_key_reply async_accept_host_key(const std::string &host_name, const std::string &algorithm,
		const pinch::blob &key, host_key_state state, Handler &handler, Executor &executor)
	{
		std::packaged_task<host_key_reply()> validate_task(
			[&] { return handler(host_name, algorithm, key, state); });

		auto result = validate_task.get_future();

		boost::asio::dispatch(executor, [task = std::move(validate_task)]() mutable { task(); });

		result.wait();

		return result.get();
	}

	/// \brief async password support
	template <typename Handler, typename Executor>
	std::string async_provide_password(Handler &handler, Executor &executor)
	{
		std::packaged_task<std::string()> validate_task(
			[&] { return handler(); });

		auto result = validate_task.get_future();

		boost::asio::dispatch(executor, [task = std::move(validate_task)]() mutable { task(); });

		result.wait();

		return result.get();
	}

	/// \brief async credentials support
	template <typename Handler, typename Executor>
	std::vector<std::string> async_provide_credentials(const std::string &name,
		const std::string &instruction, const std::string &lang, const std::vector<prompt> &prompts,
		Handler &handler, Executor &executor)
	{
		std::packaged_task<std::vector<std::string>()> validate_task(
			[&] { return handler(name, instruction, lang, prompts); });

		auto result = validate_task.get_future();

		boost::asio::dispatch(executor, [task = std::move(validate_task)]() mutable { task(); });

		result.wait();

		return result.get();
	}

	std::string m_user;
	std::string m_host;
	uint16_t m_port;

	std::string m_host_version;
	blob m_session_id;

	crypto_engine m_crypto_engine;

	enum
	{
		none,
		handshake,
		authenticated
	} m_auth_state = none;

	// Keep track of I/O operations in order to be able to send keep-alive
	// messages
	using time_point_type = std::chrono::time_point<std::chrono::steady_clock>;
	time_point_type m_last_io;
	blob m_private_key_hash;
	boost::asio::streambuf m_response;

	provide_password_callback_type m_provide_password_handler;
	provide_credentials_callback_type m_provide_credentials_handler;
	accept_host_key_handler_type m_accept_host_key_handler;

	std::list<channel_ptr> m_channels;
	bool m_forward_agent;
	std::shared_ptr<port_forward_listener> m_port_forwarder;

	// for rekeying
	std::unique_ptr<key_exchange> m_kex;

	// --------------------------------------------------------------------

	struct async_read_impl
	{
		template <typename Handler, typename MutableBufferSequence>
		void operator()(Handler &&handler, basic_connection *connection,
			const MutableBufferSequence &buffers);
	};

	struct async_write_impl
	{
		template <typename Handler, typename ConstBufferSequence>
		void operator()(Handler &&handler, basic_connection *connection,
			const ConstBufferSequence &buffers);
	};

	struct async_wait_impl
	{
		template <typename Handler>
		void operator()(Handler &&handler, basic_connection *connection,
			wait_type type);
	};
};

// --------------------------------------------------------------------

class connection : public basic_connection
{
  public:
	template <typename Arg>
	connection(Arg &&arg, const std::string &user, const std::string &host,
		uint16_t port)
		: basic_connection(user, host, port)
		, m_next_layer(std::forward<Arg>(arg))
	{
		reset();
	}

	/// The type of the next layer.
	using next_layer_type = boost::asio::ip::tcp::socket;

	virtual executor_type get_executor() noexcept override
	{
		return m_next_layer.lowest_layer().get_executor();
	}

	const next_layer_type &next_layer() const { return m_next_layer; }

	next_layer_type &next_layer() { return m_next_layer; }

	const lowest_layer_type &lowest_layer() const override
	{
		return m_next_layer.lowest_layer();
	}

	lowest_layer_type &lowest_layer() override
	{
		return m_next_layer.lowest_layer();
	}

	virtual void disconnect() override
	{
		basic_connection::disconnect();

		m_next_layer.close();
	}

	virtual void open() override;

	virtual bool is_open() const override { return m_next_layer.is_open(); }

  private:
	boost::asio::ip::tcp::socket m_next_layer;
};

// --------------------------------------------------------------------

class proxied_connection : public basic_connection
{
  public:
	proxied_connection(std::shared_ptr<basic_connection> proxy,
		const std::string &nc_cmd, const std::string &user,
		const std::string &host, uint16_t port = 22);

	proxied_connection(std::shared_ptr<basic_connection> proxy,
		const std::string &user, const std::string &host,
		uint16_t port = 22);

	~proxied_connection();

	/// The type of the next layer.
	using next_layer_type = channel;

	virtual executor_type get_executor() noexcept override;

	const next_layer_type &next_layer() const { return *m_channel; }

	next_layer_type &next_layer() { return *m_channel; }

	const lowest_layer_type &lowest_layer() const override;

	lowest_layer_type &lowest_layer() override;

	virtual void disconnect() override;

	virtual void open() override;
	virtual bool is_open() const override;

  private:
	friend async_wait_impl;

	void do_wait(std::unique_ptr<detail::wait_connection_op> op);

	std::shared_ptr<basic_connection> m_proxy;
	std::shared_ptr<channel> m_channel;
	std::string m_host;
};

// --------------------------------------------------------------------

template <typename Handler, typename MutableBufferSequence>
void basic_connection::async_read_impl::operator()(
	Handler &&handler, basic_connection *conn,
	const MutableBufferSequence &buffers)
{
	auto c = dynamic_cast<connection *>(conn);
	if (c)
		boost::asio::async_read(c->next_layer(), buffers,
			boost::asio::transfer_at_least(1),
			std::move(handler));
	else
	{
		auto pc = dynamic_cast<proxied_connection *>(conn);
		if (pc)
			boost::asio::async_read(pc->next_layer(), buffers,
				boost::asio::transfer_at_least(1),
				std::move(handler));
	}
}

template <typename Handler, typename ConstBufferSequence>
void basic_connection::async_write_impl::operator()(
	Handler &&handler, basic_connection *conn,
	const ConstBufferSequence &buffers)
{
	auto c = dynamic_cast<connection *>(conn);
	if (c)
		boost::asio::async_write(c->next_layer(), buffers, std::move(handler));
	else
	{
		auto pc = dynamic_cast<proxied_connection *>(conn);
		if (pc)
			boost::asio::async_write(pc->next_layer(), buffers, std::move(handler));
	}
}

template <typename Handler>
void basic_connection::async_wait_impl::operator()(
	Handler &&handler, basic_connection *conn,
	basic_connection::wait_type type)
{
	auto c = dynamic_cast<connection *>(conn);
	auto pc = dynamic_cast<proxied_connection *>(conn);

	assert(!c != !pc);

	switch (type)
	{
		case wait_type::read:
			if (c)
				c->next_layer().async_wait(boost::asio::socket_base::wait_read,
					std::move(handler));
			else
				pc->do_wait(std::unique_ptr<detail::wait_connection_op>(
					new detail::wait_connection_handler(std::move(handler),
						pc->get_executor(), type)));
			break;

		case wait_type::write:
			if (c)
				c->next_layer().async_wait(boost::asio::socket_base::wait_write,
					std::move(handler));
			else
				pc->do_wait(std::unique_ptr<detail::wait_connection_op>(
					new detail::wait_connection_handler(std::move(handler),
						pc->get_executor(), type)));
			break;

		default:
			assert(false);
	}
}

// --------------------------------------------------------------------

namespace detail
{

	template <typename Self>
	void async_connect_impl::operator()(Self &self, boost::system::error_code ec,
		std::size_t bytes_transferred)
	{
		if (ec)
		{
			failed(self, ec);
			return;
		}

		switch (state)
		{
			case state_type::connect:
				if (not conn->is_open())
					conn->open();
				state = state_type::start;
				conn->async_wait(connection::wait_type::write, std::move(self));
				return;

			case state_type::start:
			{
				std::ostream out(request.get());
				out << kSSHVersionString << "\r\n";
				state = state_type::wrote_version;
				boost::asio::async_write(*conn, *request, std::move(self));
				return;
			}

			case state_type::wrote_version:
				state = state_type::reading;
				boost::asio::async_read_until(*conn, response, "\n", std::move(self));
				return;

			case state_type::reading:
			{
				std::istream response_stream(&response);
				std::getline(response_stream, host_version);
				while (std::isspace(host_version.back()))
					host_version.pop_back();

				if (host_version.substr(0, 7) != "SSH-2.0")
				{
					failed(self,
						error::make_error_code(error::protocol_version_not_supported));
					return;
				}

				state = state_type::rekeying;

				kex = std::make_unique<key_exchange>(host_version,
					std::bind(&connection::accept_host_key, conn, std::placeholders::_1, std::placeholders::_2));

				conn->async_write(kex->init());

				boost::asio::async_read(*conn, response,
					boost::asio::transfer_at_least(8),
					std::move(self));
				return;
			}

			case state_type::rekeying:
			{
				for (;;)
				{
					if (not conn->receive_packet(*packet, ec) and not ec)
					{
						boost::asio::async_read(*conn, response,
							boost::asio::transfer_at_least(1),
							std::move(self));
						return;
					}

					opacket out;
					if (*packet == msg_newkeys)
					{
						conn->newkeys(*kex, ec);

						if (ec)
						{
							failed(self, ec);
							return;
						}

						state = state_type::authenticating;

						out = msg_service_request;
						out << "ssh-userauth";

						// we might not be known yet
						ssh_agent::instance().register_connection(conn);

						// fetch the private keys
						for (auto &pk : ssh_agent::instance())
						{
							opacket blob;
							blob << pk;
							private_keys.push_back(blob);
						}
					}
					else if (not kex->process(*packet, out, ec))
					{
						if (not ec)
							ec = error::make_error_code(error::key_exchange_failed);
					}

					if (ec)
					{
						failed(self, ec);
						return;
					}

					if (out)
						conn->async_write(std::move(out));

					packet->clear();
				}
			}

			case state_type::authenticating:
			{
				for (;;)
				{
					if (not conn->receive_packet(*packet, ec) and not ec)
					{
						boost::asio::async_read(*conn, response,
							boost::asio::transfer_at_least(1),
							std::move(self));
						return;
					}

					auto &in = *packet;
					opacket out;

					switch ((message_type)in)
					{
						case msg_service_accept:
							out = msg_userauth_request;
							out << user << "ssh-connection"
								<< "none";
							break;

						case msg_userauth_failure:
							process_userauth_failure(in, out, ec);
							break;

						case msg_userauth_banner:
						{
							std::string msg, lang;
							in >> msg >> lang;
							conn->handle_banner(msg, lang);
							break;
						}

						case msg_userauth_info_request:
							process_userauth_info_request(in, out, ec);
							break;

						case msg_userauth_success:
							conn->userauth_success(host_version, kex->session_id(),
								private_key_hash);
							self.complete({});
							return;

						default:
#if DEBUG
							std::cerr << "Unexpected packet: " << in << std::endl;
#endif
							break;
					}

					if (ec)
					{
						failed(self, ec);
						return;
					}

					if (out)
						conn->async_write(std::move(out));

					packet->clear();
				}
			}
		}
	}

	template <typename Self>
	void async_connect_impl::failed(Self &self, boost::system::error_code ec)
	{
		conn->handle_error(ec);
		self.complete(ec);
	}

} // namespace detail

} // namespace pinch
