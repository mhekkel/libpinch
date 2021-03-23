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
// #include <coroutine>

// #include <boost/asio/use_awaitable.hpp>
#include <boost/asio/spawn.hpp>

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

/// \brief The reply from the accept_host_key callback.
enum class host_key_reply
{
	reject,     ///< Do not trust this host key and abort connecting
	trust_once, ///< Trust the host key, but do not store it for future use
	trusted     ///< Trust the key and store it
};

/// \brief The callback signature for accepting unknown or invalid host keys
using accept_host_key_handler_type = std::function<host_key_reply(const std::string &host, const std::string &algorithm, const blob &key, host_key_state state)>;

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
		open,
		read,
		write
	};

	// --------------------------------------------------------------------

	class open_connection_op : public operation
	{
	};

	template <typename Handler, typename IoExecutor>
	class open_connection_handler : public open_connection_op
	{
	  public:
		open_connection_handler(Handler &&h, const IoExecutor &io_ex)
			: m_handler(std::forward<Handler>(h))
			, m_io_executor(io_ex)
			, m_work(m_handler, m_io_executor)
		{
		}

		void complete(const boost::system::error_code &ec = {}, std::size_t bytes_transferred = 0) override
		{
			binder<Handler, boost::system::error_code> handler(m_handler, ec);
			m_work.complete(handler, handler.m_handler);
		}

	  private:
		Handler m_handler;
		IoExecutor m_io_executor;
		handler_work<Handler, IoExecutor> m_work;
	};

	// --------------------------------------------------------------------

	class wait_connection_op : public operation
	{
	  public:
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

		void complete(const boost::system::error_code &ec = {},
			std::size_t bytes_transferred = 0) override
		{
			binder<Handler, boost::system::error_code> handler(m_handler, ec);
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

	virtual ~basic_connection() {}

	/// The type of the lowest layer.
	using tcp_socket_type = boost::asio::ip::tcp::socket;
	using lowest_layer_type = typename tcp_socket_type::lowest_layer_type;

	/// The type of the executor associated with the object.
	using executor_type = typename lowest_layer_type::executor_type;

	virtual executor_type get_executor() noexcept = 0;
	virtual lowest_layer_type &lowest_layer() = 0;
	virtual const lowest_layer_type &lowest_layer() const = 0;

	/// \brief The io_context
	virtual boost::asio::io_context &get_io_context() = 0;

	/// \brief Return the proxy for this connection, or null if this is a direct connection
	virtual basic_connection *get_proxy() const
	{
		return nullptr;
	}

	virtual void open() = 0;

	virtual bool is_open() const
	{
		return next_layer_is_open() and m_auth_state == authenticated;
	}

	virtual void close();

	void rekey();
	void keep_alive();

  protected:
	virtual bool next_layer_is_open() const = 0;

	template <typename Handler>
	auto async_open_next_layer(Handler &&handler)
	{
		return boost::asio::async_initiate<Handler,
			void(boost::system::error_code)>(
			async_open_next_layer_impl{}, handler, this);
	}

  public:
	template <typename Handler>
	auto async_open(Handler &&handler)
	{
		return boost::asio::async_initiate<
			Handler, void(boost::system::error_code, std::size_t)>(
			async_open_impl{}, handler, this);
	}

	using wait_type = detail::connection_wait_type;

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

	void forward_port(uint16_t local_port, const std::string &remote_address, uint16_t remote_port);

	void forward_socks5(uint16_t local_port);

	std::string get_connection_parameters(direction dir) const
	{
		return m_crypto_engine.get_connection_parameters(dir);
	}

	std::string get_key_exchange_algorithm() const
	{
		return m_crypto_engine.get_key_exchange_algorithm();
	}

	/// \brief Returns true if the connection uses the public key \a pk_hash
	bool uses_private_key(const blob &pk_hash)
	{
		return m_private_key_hash == pk_hash;
	}

	template<typename Executor>
	void set_callback_executor(Executor executor)
	{
		m_callback_executor = executor;
	}

	/// \brief Return true if the connection should accept the host key \a key
	/// and algorithm \a algorithm when connecting to host \a host
	///
	/// This function delegates the question to known_hosts first which will in
	/// turn call the registered callback when needed. The reason for this route
	/// is to allow per-connection validation, making feedback to the user easier.

	bool accept_host_key(const std::string &algorithm, const blob &key)
	{
		auto state = known_hosts::instance().accept_host_key(m_host, algorithm, key);

		bool result = state == host_key_state::match;
		if (not result and m_accept_host_key_handler)
		{
			switch (m_accept_host_key_handler(m_host, algorithm, key, state))
			{
				case host_key_reply::trusted:
					known_hosts::instance().add_host_key(m_host, algorithm, key);

				case host_key_reply::trust_once:
					result = true;
					break;

				default:
					break;
			}
		}

		return result;
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

		m_accept_host_key_handler = boost::asio::bind_executor(executor, std::move(handler));
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

		m_provide_password_handler = boost::asio::bind_executor(executor, std::move(handler));
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

		m_provide_credentials_handler = boost::asio::bind_executor(executor, std::move(handler));
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

	virtual void open_next_layer(std::unique_ptr<detail::wait_connection_op> op) = 0;

	bool receive_packet(ipacket &packet, boost::system::error_code &ec);

	void received_data(boost::system::error_code ec);

	void process_packet(ipacket &in);
	void process_channel_open(ipacket &in, opacket &out);
	void process_channel(ipacket &in, opacket &out,
		boost::system::error_code &ec);

	void handle_banner(const std::string &message, const std::string &lang);

	// --------------------------------------------------------------------

//   protected:
public:
	/// \brief async accept_host_key support
	template <typename Handler>
	auto async_check_host_key(const std::string &algorithm, const pinch::blob &key, Handler &&handler)
	{
		auto executor = m_callback_executor;
		if (not executor)
			executor = boost::asio::get_associated_executor(m_accept_host_key_handler);
		return async_function_wrapper(std::move(handler), executor, std::bind(&basic_connection::accept_host_key, this, std::placeholders::_1, std::placeholders::_2), algorithm, key);
	}

	/// \brief async password support
	template <typename Handler>
	auto async_provide_password(Handler &&handler)
	{
		auto executor = m_callback_executor;
		if (not executor)
			executor = boost::asio::get_associated_executor(m_provide_password_handler);
		return async_function_wrapper(std::move(handler), executor, std::bind(&basic_connection::provide_password, this));
	}

	/// \brief async credentials support
	template <typename Handler>
	auto async_provide_credentials(const std::string &name, const std::string &instruction,
		const std::string &lang, const std::vector<prompt> &prompts, Handler &&handler)
	{
		auto executor = m_callback_executor;
		if (not executor)
			executor = boost::asio::get_associated_executor(m_provide_credentials_handler);
		return async_function_wrapper(std::move(handler), executor,
			std::bind(&basic_connection::provide_credentials, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4),
			name, instruction, lang, prompts);
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
	boost::asio::execution::any_executor<boost::asio::execution::blocking_t::never_t> m_callback_executor;

	std::list<channel_ptr> m_channels;
	bool m_forward_agent;
	std::shared_ptr<port_forward_listener> m_port_forwarder;

	// what is waiting
	std::deque<detail::wait_connection_op *> m_waiting_ops;

	// for rekeying
	std::unique_ptr<key_exchange> m_kex;

	// --------------------------------------------------------------------

	struct async_open_next_layer_impl
	{
		template <typename Handler>
		void operator()(Handler &&handler, basic_connection *connection);
	};

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

	struct async_open_impl
	{
		template <typename Handler>
		void operator()(Handler &&handler, basic_connection *connection);
	};

	friend struct async_open_impl;

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

	void do_open(std::unique_ptr<detail::open_connection_op> op);
	void do_open_2(std::unique_ptr<detail::open_connection_op> op, boost::asio::yield_context yield);
	// boost::asio::awaitable<void> do_open_3(std::unique_ptr<detail::open_connection_op> op);

	std::unique_ptr<detail::open_connection_op> m_open_op;
};

// --------------------------------------------------------------------

class connection : public basic_connection
{
  public:
	connection(boost::asio::io_context &io_context, const std::string &user, const std::string &host,
		uint16_t port)
		: basic_connection(user, host, port)
		, m_io_context(io_context)
		, m_next_layer(m_io_context)
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

	virtual void close() override
	{
		basic_connection::close();

		m_next_layer.close();
	}

	virtual void open() override;

	virtual bool next_layer_is_open() const override
	{
		return m_next_layer.is_open();
	}

	boost::asio::io_context &get_io_context() override
	{
		return m_io_context;
	}

  private:
	void open_next_layer(std::unique_ptr<detail::wait_connection_op> op) override;

	friend async_open_next_layer_impl;

	boost::asio::io_context &m_io_context;
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

	basic_connection *get_proxy() const override
	{
		return m_proxy.get();
	}

	virtual void close() override;

	virtual void open() override;

	virtual bool next_layer_is_open() const override;

	boost::asio::io_context &get_io_context() override
	{
		return m_proxy->get_io_context();
	}

  private:
	friend async_wait_impl;
	friend async_open_next_layer_impl;

	void do_wait(std::unique_ptr<detail::wait_connection_op> op);
	void open_next_layer(std::unique_ptr<detail::wait_connection_op> op) override;

	std::shared_ptr<basic_connection> m_proxy;
	std::shared_ptr<channel> m_channel;
	std::string m_host;
};

// --------------------------------------------------------------------

template <typename Handler>
void basic_connection::async_open_impl::operator()(Handler &&handler, basic_connection *connection)
{
	connection->do_open(
		std::unique_ptr<detail::open_connection_op>(
			new detail::open_connection_handler(std::move(handler), connection->get_executor())));
}

template <typename Handler>
void basic_connection::async_open_next_layer_impl::operator()(Handler &&handler, basic_connection *connection)
{
	connection->open_next_layer(
		std::unique_ptr<detail::wait_connection_op>(
			new detail::wait_connection_handler(std::move(handler), connection->get_executor(), wait_type::open)));
}

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
		case wait_type::open:
			if (c)
				c->next_layer().async_wait(boost::asio::socket_base::wait_read,
					std::move(handler));
			else
				pc->do_wait(std::unique_ptr<detail::wait_connection_op>(
					new detail::wait_connection_handler(std::move(handler),
						pc->get_executor(), type)));
			break;

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

} // namespace pinch

