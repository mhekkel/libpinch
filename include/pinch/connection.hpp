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

	// --------------------------------------------------------------------

	/// \brief An operation that opens a connection

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

	/// \brief enum used in connection::async_wait
	enum class connection_wait_type
	{
		open,
		read,
		write
	};

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
/// \brief The abstract base class for connections
///
/// This is the core class of libpinch. It maintains a connection to a server,
/// provides the handshake code and manages channels over this connection.
///
/// A connection has a `next layer` that implements a boost stream, it is over
/// this next layer that connection send and retrieves its data.
///
/// There are two implementations of this base class: connection and proxied_connection.
/// The first uses a tcp::socket as next layer, the second a channel. That way
/// you can stack connections on each other allowing one to hop from one server to
/// another.

class basic_connection : public std::enable_shared_from_this<basic_connection>
{
  protected:
	/// \brief The constructor is protected. Not useful anyway since this class is abstract.
	///
	/// \param user	The user name to use when logging in
	/// \param host The hostname to connect to, or an IP address
	/// \param port The port to connect to

	basic_connection(boost::asio::io_context &io_context, const std::string &user, const std::string &host, uint16_t port = 22)
		: m_user(user)
		, m_host(host)
		, m_port(port)
		, m_io_context(io_context)
		, m_strand(m_io_context.get_executor())
		, m_keep_alive_timer(m_io_context)
		, m_callback_executor(io_context.get_executor())
	{
	}

	basic_connection(const basic_connection &) = delete;
	basic_connection &operator=(const basic_connection &) = delete;

  public:
	virtual ~basic_connection() {}

	/// The type of the lowest layer. In our case that's always a tcp::socket
	/// making the code easier.
	using tcp_socket_type = boost::asio::ip::tcp::socket;
	using lowest_layer_type = typename tcp_socket_type::lowest_layer_type;

	/// The type of the executor associated with the object.
	using executor_type = typename boost::asio::io_context::executor_type;

	executor_type get_executor() noexcept
	{
		return m_io_context.get_executor();
	}

	/// Access to the lowest layer
	virtual lowest_layer_type &lowest_layer() = 0;
	virtual const lowest_layer_type &lowest_layer() const = 0;

	/// \brief Open means, the next layer is open (socket e.g.)
	/// and the authentication has completed successfully.
	virtual bool is_open() const
	{
		return next_layer_is_open() and m_auth_state == authenticated;
	}

	/// \brief Asynchronously connect the next layer and then
	/// perform a handshake and log in to the server.
	///
	/// \param handler The completion handler, should be of form
	///                void (boost::system::error_code)
	template <typename Handler>
	auto async_open(Handler &&handler)
	{
		return boost::asio::async_initiate<
			Handler, void(boost::system::error_code, std::size_t)>(
			async_open_impl{}, handler, this);
	}

	/// \brief Close the connection
	virtual void close();

	/// \brief Start a rekeying session. This will replace the
	/// current session keys with new ones.
	void rekey();

	/// \brief If you want to keep the connection alive, even without
	/// any traffic, you should call this method specifying the time between
	/// the dummy packets.
	///
	/// Internally, connection keeps track of when the last I/O took
	/// place and if this call is made within the kKeepAliveInterval
	/// nothing will happen.
	void keep_alive(std::chrono::seconds interval = std::chrono::seconds(60));

  protected:
	/// \brief Return true if the next layer is open.
	virtual bool next_layer_is_open() const = 0;

	/// \brief Asynchronously open the next layer.
	///
	/// \param handler The completion handler, should be of form
	///                void (boost::system::error_code)
	template <typename Handler>
	auto async_open_next_layer(Handler &&handler)
	{
		return boost::asio::async_initiate<Handler,
			void(boost::system::error_code)>(
			async_open_next_layer_impl{}, handler, this);
	}

  public:
	/// \brief Copy of the wait_type
	using wait_type = detail::connection_wait_type;

	/// \brief Asynchronously wait for the connection to be
	/// ready to read or write, or for the connection to open.
	///
	/// \param type		The wait type: open, read or write
	/// \param handler	The completion handler, should be of form
	///               	void (boost::system::error_code)
	template <typename Handler>
	auto async_wait(wait_type type, Handler &&handler)
	{
		return boost::asio::async_initiate<Handler,
			void(boost::system::error_code)>(
			async_wait_impl{}, handler, this, type);
	}

	/// \brief Asynchronously write an complete SSH packet.
	///
	/// \param p		The packet to write.
	/// \param handler	The completion handler, should be of form
	///               	void (boost::system::error_code, std::size_t)
	template <typename Handler>
	auto async_write(opacket &&p, Handler &&handler)
	{
		enum
		{
			start,
			writing
		};

		auto buffer = m_crypto_engine.get_next_request(std::move(p));

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

	/// \brief A simple variant to write the packet \a out without the need for a handler
	void async_write(opacket &&out)
	{
		async_write(std::move(out),
			[this](const boost::system::error_code &ec, std::size_t) {
				if (ec)
					this->handle_error(ec);
			});
	}

	/// \brief To meet the requirements for AsyncWriteStream
	template <typename ConstBufferSequence, typename WriteHandler>
	auto async_write_some(const ConstBufferSequence &buffers,
		WriteHandler &&handler)
	{
		return boost::asio::async_initiate<
			WriteHandler, void(boost::system::error_code, std::size_t)>(
			async_write_impl{}, handler, this, buffers);
	}

	/// \brief To meet the requirements for AsyncReadStream
	template <typename MutableBufferSequence, typename ReadHandler>
	auto async_read_some(const MutableBufferSequence &buffers,
		ReadHandler &&handler)
	{
		return boost::asio::async_initiate<
			ReadHandler, void(boost::system::error_code, std::size_t)>(
			async_read_impl{}, handler, this, buffers);
	}

	/// \brief Should be called before opening a connection,
	/// will add a separate channel that forwards the SSH agent.
	void forward_agent(bool forward) { m_forward_agent = forward; }

	/// \brief Create an SSH tunnel.
	///
	/// This call will start listening on \a local_port for connections
	/// and when it accepts a connection it will wire up this connection
	/// to the server at \a remote_address and port \a remote_port using
	/// a new channel.
	void forward_port(uint16_t local_port, const std::string &remote_address, uint16_t remote_port);

	/// \brief Create a SOCKS5 proxy over an SSH tunnel.
	///
	/// This call will start listening on \a local_port for connections
	/// and will provide a full SOCKS5 server implementation.
	void forward_socks5(uint16_t local_port);

	/// \brief Return the connection parameters in a string for direction \a dir
	std::string get_connection_parameters(direction dir) const
	{
		return m_crypto_engine.get_connection_parameters(dir);
	}

	/// \brief Return the key exchange algorithm used in connecting
	std::string get_key_exchange_algorithm() const
	{
		return m_crypto_engine.get_key_exchange_algorithm();
	}

	/// \brief Returns true if the connection uses the public key \a pk_hash
	bool uses_private_key(const blob &pk_hash)
	{
		return m_private_key_hash == pk_hash;
	}

	/// \brief Set the callback executor to use
	///
	/// This will ensure the callbacks, like host validation and password providers
	/// are called using \a executor. This will help you to ensure callbacks are
	/// made on the main graphics thread.

	using callback_executor_type = boost::asio::execution::any_executor<boost::asio::execution::blocking_t::never_t>;

	void set_callback_executor(callback_executor_type executor)
	{
		m_callback_executor = executor;
	}

	/// \brief Return true if the connection should accept the host key \a key
	/// and algorithm \a algorithm when connecting to host \a host
	///
	/// This function delegates the question to known_hosts first. If the key
	/// is unknown or changed, the registered callback is asked what to do.

	template <typename Handler>
	auto async_accept_host_key(const std::string &algorithm, const blob &key, Handler &&handler)
	{
		enum
		{
			start,
			ask
		};

		return boost::asio::async_compose<Handler, void(boost::system::error_code, bool)>(
			[state1 = start, this, state = host_key_state::no_match, algorithm, key](auto &self, boost::system::error_code ec = {}, bool accept = {}) mutable {
				if (not ec)
				{
					switch (state1)
					{
						case start:
						{
							state = known_hosts::instance().accept_host_key(m_host, algorithm, key);

							bool result = state == host_key_state::match;
							if (result or not m_accept_host_key_handler)
								self.complete(ec, false);
							else
							{
								state1 = ask;
								boost::asio::execution::execute(
									boost::asio::require(m_callback_executor, boost::asio::execution::blocking.never),
									std::move(self));
							}
							return;
						}

						case ask:
						{
							switch (m_accept_host_key_handler(m_host, algorithm, key, state))
							{
								case host_key_reply::trusted:
									known_hosts::instance().add_host_key(m_host, algorithm, key);

								case host_key_reply::trust_once:
									accept = true;
									break;

								default:
									break;
							}
						}
					}

					self.complete(ec, accept);
				}
			},
			handler);
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

	/// \brief Call provide password asynchronously
	template <typename Handler>
	auto async_provide_password(Handler &&handler)
	{
		enum
		{
			start,
			running
		};

		return boost::asio::async_compose<Handler, void(boost::system::error_code, std::string)>(
			[state = start,
				this](auto &self, boost::system::error_code ec = {}, std::string pw = {}) mutable {
				if (not ec)
				{
					if (state == start)
					{
						state = running;
						boost::asio::execution::execute(
							boost::asio::require(m_callback_executor, boost::asio::execution::blocking.never),
							std::move(self));
						return;
					}

					pw = m_provide_password_handler();
				}

				self.complete(ec, pw);
			},
			handler);
	}

	/// \brief register a function that will return a password to use in connecting
	///
	/// The callback \a handler will be called using the aforementioned executor,
	/// potentially running in a separate thread.
	/// All I/O will be blocked in this thread until a reply is received.

	template <typename Handler>
	void set_provide_password_callback(Handler &&handler)
	{
		static_assert(std::is_assignable_v<provide_password_callback_type, decltype(handler)>, "Invalid handler");

		m_provide_password_handler = handler;
	}

	/// \brief Simply run the provide credentials handler
	template <typename Handler>
	auto async_provide_credentials(const std::string &name,
		const std::string &instruction, const std::string &lang,
		const std::vector<prompt> &prompts, Handler &&handler)
	{
		enum
		{
			start,
			running
		};

		return boost::asio::async_compose<Handler, void(boost::system::error_code, std::vector<std::string>)>(
			[state = start,
				name, instruction, lang, prompts,
				this](auto &self, const boost::system::error_code &ec = {}, std::vector<std::string> reply = {}) mutable {
				if (not ec)
				{
					if (state == start)
					{
						state = running;
						boost::asio::execution::execute(
							boost::asio::require(m_callback_executor, boost::asio::execution::blocking.never),
							std::move(self));
						return;
					}

					reply = m_provide_credentials_handler(name, instruction, lang, prompts);
				}

				self.complete(ec, reply);
			},
			handler);
	}

	/// \brief register a function that will return the credentials for a connection
	/// as requested by the keyboard-interactive method.
	///
	/// The callback \a handler will be called using the aforementioned executor,
	/// potentially running in a separate thread.
	/// All I/O will be blocked in this thread until a reply is received.

	template <typename Handler>
	void set_provide_credentials_callback(Handler &&handler)
	{
		static_assert(std::is_assignable_v<provide_credentials_callback_type, decltype(handler)>, "Invalid handler");

		m_provide_credentials_handler = handler;
	}

	/// \brief Open channel \a ch with channel ID \a id
	void open_channel(channel_ptr ch, uint32_t id);

	/// \brief Close channel \a ch with channel ID \a id
	void close_channel(channel_ptr ch, uint32_t id);

	/// \brief Are there any channels still open?
	bool has_open_channels();

  protected:
	/// \brief Open the next layer with \a op as completion operation
	virtual void open_next_layer(std::unique_ptr<detail::wait_connection_op> op) = 0;

	/// \brief Handle the error in \a ec, communicate the message over all channels and close the connection
	virtual void handle_error(const boost::system::error_code &ec);

	/// \brief Start using the new keys in \a kex
	void newkeys(key_exchange &kex)
	{
		m_crypto_engine.newkeys(kex, m_auth_state == authenticated);
	}

	/// \brief Authentication has succesfully ended, store the relevant information
	void userauth_success(const std::string &host_version, const blob &session_id,
		const blob &pk_hash);

	/// \brief Internal dispatching routine for packets.
	///
	/// This method is used by the handshake code to fetch the next packet
	bool receive_packet(ipacket &packet, boost::system::error_code &ec);

	/// \brief dispatch an incomming packet
	void process_packet(ipacket &in);

	/// \brief handle the opening of a channel (used for x11 forwarding and ssh-agent requests)
	void process_channel_open(ipacket &in, opacket &out);

	/// \brief dispatch packets targeted at a channel
	void process_channel(ipacket &in);

	/// \brief A banner might arrive during the handshake phase, communicate it over the opening channels
	void handle_banner(const std::string &message, const std::string &lang);

	// --------------------------------------------------------------------

	std::string m_user;           ///< The username
	std::string m_host;           ///< The hostname or IP address
	uint16_t m_port;              ///< The port number
	bool m_forward_agent = false; ///< Flag indicating we want to forward the SSH agent

	boost::asio::io_context &m_io_context;
	boost::asio::strand<boost::asio::io_context::executor_type> m_strand; ///< for our coroutines

	std::string m_host_version; ///< The host version string, used for generating keys
	blob m_session_id;          ///< The session ID for this session

	crypto_engine m_crypto_engine; ///< The crypto engine

	enum
	{
		none,              ///< Not connected yet, or disconnected
		handshake,         ///< In the handshaking phase
		authenticated      ///< Fully authenticated
	} m_auth_state = none; ///< The authentication state

	// Keep track of I/O operations in order to be able to send keep-alive
	// messages
	using time_point_type = std::chrono::time_point<std::chrono::steady_clock>;

	time_point_type m_last_io;                                          ///< The last time we had an I/O
	std::chrono::seconds m_keep_alive_interval;                         ///< How often should we send keep alive packets (in seconds)?
	boost::asio::steady_timer m_keep_alive_timer;                       ///< The timer used for keep alive
	void keep_alive_time_out(const boost::system::error_code &ec = {}); ///< Callback for the keep alive timer

	blob m_private_key_hash;           ///< The private key used to authenticate
	boost::asio::streambuf m_response; ///< Buffer for incomming response data

	provide_password_callback_type m_provide_password_handler;       ///< The registered password handler
	provide_credentials_callback_type m_provide_credentials_handler; ///< The registered keyboard-interactive handler
	accept_host_key_handler_type m_accept_host_key_handler;          ///< The registered host key validation handler

	/// \brief The executor for the handlers above
	callback_executor_type m_callback_executor;

	std::list<channel_ptr> m_channels;                       ///< The currently registered channels
	std::shared_ptr<port_forward_listener> m_port_forwarder; ///< The port forwarder

	std::deque<detail::wait_connection_op *> m_waiting_ops; ///< what is waiting
	std::unique_ptr<key_exchange> m_kex;                    ///< for rekeying

	// --------------------------------------------------------------------

	/// \brief Helper class for opening the next layer
	struct async_open_next_layer_impl
	{
		template <typename Handler>
		void operator()(Handler &&handler, basic_connection *connection);
	};

	/// \brief Helper class for async reading
	struct async_read_impl
	{
		template <typename Handler, typename MutableBufferSequence>
		void operator()(Handler &&handler, basic_connection *connection,
			const MutableBufferSequence &buffers);
	};

	/// \brief Helper class for async writing
	struct async_write_impl
	{
		template <typename Handler, typename ConstBufferSequence>
		void operator()(Handler &&handler, basic_connection *connection,
			const ConstBufferSequence &buffers);
	};

	/// \brief Helper class for async waiting
	struct async_wait_impl
	{
		template <typename Handler>
		void operator()(Handler &&handler, basic_connection *connection,
			wait_type type);
	};

	/// \brief Helper class for opening the connection
	struct async_open_impl
	{
		template <typename Handler>
		void operator()(Handler &&handler, basic_connection *connection);
	};

	friend struct async_open_impl;

  private:
	/// \brief The 'main loop' for reading incoming data
	void read_loop(boost::system::error_code ec = {}, std::size_t bytes_transferred = 0);

	/// \brief The actual opening code
	void do_open(std::unique_ptr<detail::open_connection_op> op);

	/// \brief The handshake code
	void do_handshake(std::unique_ptr<detail::open_connection_op> op, boost::asio::yield_context yield);
	// boost::asio::awaitable<void> do_open_3(std::unique_ptr<detail::open_connection_op> op);
};

// --------------------------------------------------------------------

/// \brief An implementation of a basic connection using a tcp::socket as next layer
///
/// This class implements a regular SSH connection over a TCP socket.

class connection : public basic_connection
{
  public:
	/// \brief Constructor
	///
	/// Creates a connection, but does not open it. You need to call async_open for that.
	///
	/// \param io_context	The io_context to use for the socket
	/// \param user			The username to use when authenticating
	/// \param host			The hostname or ip address of the server to connect to
	/// \param port			The port number to connect to

	connection(boost::asio::io_context &io_context, const std::string &user, const std::string &host,
		uint16_t port = 22)
		: basic_connection(io_context, user, host, port)
		, m_io_context(io_context)
		, m_next_layer(m_io_context)
	{
	}

	/// \brief The type of the next layer.
	using next_layer_type = boost::asio::ip::tcp::socket;

	/// \brief Access to the next layer
	const next_layer_type &next_layer() const { return m_next_layer; }

	/// \brief Access to the next layer
	next_layer_type &next_layer() { return m_next_layer; }

	/// \brief Access to the lowest layer, should always be a tcp::socket
	const lowest_layer_type &lowest_layer() const override
	{
		return m_next_layer.lowest_layer();
	}

	/// \brief Access to the lowest layer, should always be a tcp::socket
	lowest_layer_type &lowest_layer() override
	{
		return m_next_layer.lowest_layer();
	}

	/// \brief Close the connection and the socket
	virtual void close() override
	{
		basic_connection::close();

		m_next_layer.close();
	}

	/// \brief Is the socket open?
	virtual bool next_layer_is_open() const override
	{
		return m_next_layer.is_open();
	}

  private:
	/// \brief Asynchronously open the socket, notifying \a op when done
	void open_next_layer(std::unique_ptr<detail::wait_connection_op> op) override;

	friend async_open_next_layer_impl;

	boost::asio::io_context &m_io_context;     ///< The IO Context we use
	boost::asio::ip::tcp::socket m_next_layer; ///< The TCP socket
};

// --------------------------------------------------------------------

/// \brief An implementation of basic_connection that uses another connection as proxy
///
/// To access hosts located behind a firewall, it is often useful to hop from one server
/// to another. By using this proxied connection class, you can benefit of being able
/// to open multiple channels over the connection without the need to reconnect.

class proxied_connection : public basic_connection
{
  public:
	/// \brief Constructor using a 'proxy command' like netcat
	///
	///	Historically, a command like /bin/nc or /usr/bin/netcat is
	///	used to establish a transparent connection to the next server.
	///	Use the next constructor if you want direct-tcpip instead.
	///
	/// \param proxy	The basic_connection to use as proxy.
	/// \param nc_cmd	The netcat command, or ProxyCommand as called in OpenSSH.
	/// \param user		The username to use when authenticating
	/// \param host		The hostname or ip address of the server to connect to
	/// \param port		The port number to connect to
	proxied_connection(std::shared_ptr<basic_connection> proxy,
		const std::string &nc_cmd, const std::string &user,
		const std::string &host, uint16_t port = 22);

	/// \brief Constructor using a direct-tcpip channel to connect to the host
	///
	///	This variant uses a direct-tcpip channel
	///
	/// \param proxy	The basic_connection to use as proxy.
	/// \param user		The username to use when authenticating
	/// \param host		The hostname or ip address of the server to connect to
	/// \param port		The port number to connect to
	proxied_connection(std::shared_ptr<basic_connection> proxy,
		const std::string &user, const std::string &host,
		uint16_t port = 22);

	/// \brief destructor
	~proxied_connection();

	/// \brief The type of the next layer.
	using next_layer_type = channel;

	/// \brief Access to the next layer
	const next_layer_type &next_layer() const { return *m_channel; }

	/// \brief Access to the next layer
	next_layer_type &next_layer() { return *m_channel; }

	/// \brief Access to the lowest layer
	const lowest_layer_type &lowest_layer() const override;

	/// \brief Access to the lowest layer
	lowest_layer_type &lowest_layer() override;

	/// \brief Close the connection
	virtual void close() override;

	/// \brief Is the proxy channel open?
	virtual bool next_layer_is_open() const override;

  private:
	friend async_wait_impl;
	friend async_open_next_layer_impl;

	/// \brief The actual wait implementation.
	void do_wait(std::unique_ptr<detail::wait_connection_op> op);

	/// \brief Open the proxy channel asynchronously, calling \a op when done
	void open_next_layer(std::unique_ptr<detail::wait_connection_op> op) override;

	std::shared_ptr<basic_connection> m_proxy; ///< The proxy connection
	std::shared_ptr<channel> m_channel;        ///< The channel in m_proxy used for this connection
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
	// I don't like this approach very much, but I see no other alternative.

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
			conn->m_waiting_ops.push_back(
				new detail::wait_connection_handler(std::move(handler), conn->get_executor(), type));
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
	}
}

} // namespace pinch
