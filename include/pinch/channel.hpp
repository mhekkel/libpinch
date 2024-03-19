//        Copyright Maarten L. Hekkelman 2013-2021
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

/// \file channel.hpp
/// Definition of the base class pinch::channel
///
/// The class channel implements the concept of a bare SSH channel.
/// It uses the pinch::connection class to send and receive data.

#include "pinch/connection.hpp"
#include "pinch/operations.hpp"

namespace pinch
{

/// \brief Constant values for the packet and window size
const uint32_t kMaxPacketSize = 0x8000, kWindowSize = 4 * kMaxPacketSize;

// --------------------------------------------------------------------

namespace detail
{

	// --------------------------------------------------------------------

	enum class channel_wait_type
	{
		open,
		read,
		write
	};

	// internal classes to implement asynchronous operations

	class open_channel_op : public operation
	{
	};

	template <typename Handler, typename IoExecutor>
	class open_channel_handler : public open_channel_op
	{
	  public:
		open_channel_handler(Handler &&h, const IoExecutor &io_ex)
			: m_handler(std::move(h))
			, m_io_executor(io_ex)
			, m_work(m_handler, m_io_executor)
		{
		}

		virtual void complete(const asio_system_ns::error_code &ec,
			std::size_t bytes_transferred = 0) override
		{
			binder<Handler, asio_system_ns::error_code> handler(m_handler, ec);

			m_work.complete(handler, handler.m_handler);
		}

	  private:
		Handler m_handler;
		IoExecutor m_io_executor;
		handler_work<Handler, IoExecutor> m_work;
	};

	class read_channel_op : public operation
	{
	  public:
		std::size_t m_bytes_transferred = 0;

		virtual std::deque<char>::iterator
		transfer_bytes(std::deque<char>::iterator begin,
			std::deque<char>::iterator end) = 0;
	};

	template <typename Handler, typename IoExecutor,
		typename MutableBufferSequence>
	class read_channel_handler : public read_channel_op
	{
	  public:
		read_channel_handler(Handler &&h, const IoExecutor &io_ex,
			MutableBufferSequence &buffers)
			: m_handler(std::move(h))
			, m_io_executor(io_ex)
			, m_work(m_handler, m_io_executor)
			, m_buffers(buffers)
		{
		}

		virtual void complete(const asio_system_ns::error_code &ec = {},
			std::size_t bytes_transferred = 0) override
		{
			binder<Handler, asio_system_ns::error_code, std::size_t> handler(
				m_handler, ec, m_bytes_transferred);

			m_work.complete(handler, handler.m_handler);
		}

		virtual std::deque<char>::iterator
		transfer_bytes(std::deque<char>::iterator begin,
			std::deque<char>::iterator end) override
		{
			std::ptrdiff_t size = asio_ns::buffer_size(m_buffers);
			if (size > end - begin)
				size = end - begin;

			for (auto buf = asio_ns::buffer_sequence_begin(m_buffers);
				 buf != asio_ns::buffer_sequence_end(m_buffers) and size > 0;
				 ++buf)
			{
				char *dst = static_cast<char *>(buf->data());

				std::size_t bsize = size;
				if (bsize > buf->size())
					bsize = buf->size();

				size -= bsize;
				m_bytes_transferred += bsize;

				while (bsize-- > 0)
					*dst++ = *begin++;
			}

			return begin;
		}

	  private:
		Handler m_handler;
		IoExecutor m_io_executor;
		handler_work<Handler, IoExecutor> m_work;
		MutableBufferSequence m_buffers;
	};

	class write_channel_op : public operation
	{
	  public:
		std::size_t m_bytes_transferred = 0;
		opacket m_packet;
	};

	template <typename Handler, typename IoExecutor>
	class write_channel_handler : public write_channel_op
	{
	  public:
		write_channel_handler(Handler &&h, const IoExecutor &io_ex, opacket &&packet, std::size_t bytes_transferred)
			: m_handler(std::forward<Handler>(h))
			, m_io_executor(io_ex)
			, m_work(m_handler, m_io_executor)
		{
			m_bytes_transferred = bytes_transferred;
			m_packet = std::move(packet);
		}

		virtual void complete(const asio_system_ns::error_code &ec = {},
			std::size_t bytes_transferred = 0) override
		{
			binder<Handler, asio_system_ns::error_code, std::size_t> handler(
				m_handler, ec, m_bytes_transferred);

			m_work.complete(handler, handler.m_handler);
		}

	  private:
		Handler m_handler;
		IoExecutor m_io_executor;
		handler_work<Handler, IoExecutor> m_work;
	};

	class wait_channel_op : public operation
	{
	  public:
		channel_wait_type m_type;
	};

	template <typename Handler, typename IoExecutor>
	class wait_channel_handler : public wait_channel_op
	{
	  public:
		wait_channel_handler(Handler &&h, const IoExecutor &io_ex,
			channel_wait_type type)
			: m_handler(std::forward<Handler>(h))
			, m_io_executor(io_ex)
			, m_work(m_handler, m_io_executor)
		{
			m_type = type;
		}

		virtual void complete(const asio_system_ns::error_code &ec = {},
			std::size_t bytes_transferred = 0) override
		{
			binder<Handler, asio_system_ns::error_code> handler(m_handler, ec);

			m_work.complete(handler, handler.m_handler);
		}

	  private:
		Handler m_handler;
		IoExecutor m_io_executor;
		handler_work<Handler, IoExecutor> m_work;
	};

} // namespace detail

// --------------------------------------------------------------------
/// \brief channel is the base class for implementing SSH channels
///
/// The channel class implements AsyncReadStream and AsyncWriteStream.

class channel : public std::enable_shared_from_this<channel>
{
  public:
	/// \brief The type of the lowest layer.
	using tcp_socket_type = asio_ns::ip::tcp::socket;
	using lowest_layer_type = typename tcp_socket_type::lowest_layer_type;

	/// \brief The type of the executor associated with the object.
	using executor_type = typename lowest_layer_type::executor_type;

	/// \brief required for AsyncReadStream and AsyncWriteStream
	executor_type get_executor() noexcept { return m_connection->get_executor(); }

	/// \brief Access to the lowest layer (the socket)
	const lowest_layer_type &lowest_layer() const
	{
		return m_connection->lowest_layer();
	}

	/// \brief Access to the lowest layer (the socket)
	lowest_layer_type &lowest_layer() { return m_connection->lowest_layer(); }

	/// \brief When opening a channel and requesting a pty, environmental variables can be specified
	///
	/// Note that virtually all enviromental variables are now ignored by the servers.
	struct environment_variable
	{
		std::string name;
		std::string value;
	};

	/// \brief The list of environmental variables together form an environment
	using environment = std::vector<environment_variable>;

	/// \brief Asynchronously open a channel
	///
	/// This call will open the underlying connection if needed and then
	/// sends out a request to the server to open a new SSH channel. Once
	/// this has finished successfully, the \a handler is called.

	template <typename Handler>
	auto async_open(Handler &&handler)
	{
		enum
		{
			start,
			open_connection,
			open_channel
		};

		return asio_ns::async_compose<Handler, void(asio_system_ns::error_code)>(
			[state = start,
				this,
				me = shared_from_this()](auto &self, const asio_system_ns::error_code ec = {}, std::size_t = {}) mutable
			{
				if (not ec)
				{
					switch (state)
					{
						case start:
							if (not m_connection->is_open())
							{
								state = open_connection;
								m_connection->async_open(std::move(self));
								return;
							}

						// fall through
						case open_connection:
							state = open_channel;
							m_my_window_size = kWindowSize;
							m_my_channel_id = s_next_channel_id++;
							m_connection->open_channel(shared_from_this(), m_my_channel_id);
							async_wait(wait_type::open, std::move(self));
							return;

						case open_channel:
							break;
					}
				}

				self.complete(ec);
			},
			handler);
	}

	/// \brief Shortcut for async_open, without a handler. Still async though
	void open();

	/// \brief Close the channel
	void close();

	/// \brief local copy of the wait_type specified above
	using wait_type = detail::channel_wait_type;

	/// \brief Wait asynchronously for the event in \a type
	template <typename Handler>
	auto async_wait(wait_type type, Handler &&handler)
	{
		return asio_ns::async_initiate<Handler,
			void(asio_system_ns::error_code)>(
			async_wait_impl{}, handler, this, type);
	}

  protected:
	/// \brief File the packet that will be sent when opening a channel
	///
	/// Certain channels need additional info in their msg_open packet
	virtual void fill_open_opacket(opacket &out);

	/// \brief Notification callback that this channel has opened
	virtual void opened();

	/// \brief Notification callback that this channel has closed
	virtual void closed();

	/// \brief Notification callback that this channel has reached end-of-file
	virtual void end_of_file();

	/// \brief Notification callback that the channel request was handled successfully
	virtual void succeeded(); // the request succeeded

  public:
	/// \brief Open the channel and allocate a pseudo terminal device to it
	///
	/// Terminal applications need a pty to function properly. Use this to
	/// allocate it. You can specify width and height of the terminal as well as
	/// additonal info.
	///
	/// \param width			The width of the terminal, in characters
	/// \param height			The height of the terminal, in lines
	/// \param terminal_type	The terminal type to use, like vt100 or xterm
	/// \param forward_agent	If true, an SSH agent forwarding channel is created
	/// \param forward_x11		If true, an X11 forwarding channel is created
	/// \param env				The list of environmental variables to set

	void open_pty(uint32_t width, uint32_t height,
		const std::string &terminal_type, bool forward_agent,
		bool forward_x11, const environment &env);

	/// \brief Send a request to the server, along with a command to execute
	///
	/// An exec_channel uses this to execute a command at the server side.
	void send_request_and_command(const std::string &request,
		const std::string &command);

	/// \brief Send a signal to the process at the server
	void send_signal(const std::string &inSignal);

	/// \brief The local channel ID for this channel
	uint32_t my_channel_id() const { return m_my_channel_id; }

	/// \brief Access to the underlying connection class
	basic_connection &get_connection() const { return *m_connection; }

	/// \brief Return whether this channel is actually open
	bool is_open() const { return m_channel_open; }

	/// \brief The callback type for message handlers.
	using message_callback_type = std::function<void(const std::string &, const std::string &)>;

	/// \brief Set the handlers for the three sources of messages
	///
	/// Events in a connection or channel may produce different kinds of
	/// text messages.
	void set_message_callbacks(message_callback_type banner_handler,
		message_callback_type message_handler,
		message_callback_type error_handler)
	{
		m_banner_handler = banner_handler;
		m_message_handler = message_handler;
		m_error_handler = error_handler;
	}

  protected:
	friend class basic_connection;

	/// \brief will call the banner handler
	virtual void banner(const std::string &msg, const std::string &lang);
	/// \brief will call the message handler
	virtual void message(const std::string &msg, const std::string &lang);
	/// \brief will call the error handler
	virtual void error(const std::string &msg, const std::string &lang);

	/// \brief dispatch an incomming channel message
	virtual void process(ipacket &in);

  public:
	// --------------------------------------------------------------------

	/// \brief Requirement for AsyncReadStream
	template <typename MutableBufferSequence, typename ReadHandler>
	auto async_read_some(const MutableBufferSequence &buffers,
		ReadHandler &&handler)
	{
		return asio_ns::async_initiate<
			ReadHandler, void(asio_system_ns::error_code, std::size_t)>(
			async_read_impl{}, handler, this, buffers);
	}

	/// \brief Requirement for AsyncWriteStream
	template <typename Handler, typename ConstBufferSequece>
	auto async_write_some(const ConstBufferSequece &buffer, Handler &&handler)
	{
		enum
		{
			start,
			sending
		};

		return asio_ns::async_compose<Handler, void(asio_system_ns::error_code, std::size_t)>(
			[me = shared_from_this(),
				buffer,
				state = start](auto &self, const asio_system_ns::error_code &ec = {}, std::size_t bytes_transferred = 0) mutable
			{
				std::size_t n = buffer.size();
				if (n > me->m_max_send_packet_size)
					n = me->m_max_send_packet_size;

				if (not ec and state == start)
				{
					opacket packet(msg_channel_data);
					packet << me->m_host_channel_id << std::string_view(static_cast<const char *>(buffer.data()), n);

					state = sending;

					me->async_write_packet(std::move(packet), std::move(self));
					return;
				}

				self.complete(ec, n);
			},
			handler);
	}

  private:
	/// \brief Internal routine for sending packets
	template <typename Handler>
	auto async_write_packet(opacket &&out, Handler &&handler)
	{
		return asio_ns::async_initiate<Handler, void(asio_system_ns::error_code,
													std::size_t)>(
			async_write_impl{}, handler, this, std::move(out));
	}

	// --------------------------------------------------------------------

  public:
	/// \brief To send data through the channel using SSH_MSG_CHANNEL_DATA messages
	template <typename Data, typename Handler>
	auto send_data(const Data &&data, message_type msg, Handler &&handler)
	{
		return asio_ns::async_compose<Handler, void(asio_system_ns::error_code, std::size_t)>(
			[me = shared_from_this(),
				data = std::move(data),
				offset = 0ULL,
				msg](auto &self, const asio_system_ns::error_code &ec = {}, std::size_t bytes_transferred = 0) mutable
			{
				std::size_t n = data.size() - offset;
				if (n > me->m_max_send_packet_size)
					n = me->m_max_send_packet_size;

				if (not ec and n > 0)
				{
					opacket packet(msg);
					packet << me->m_host_channel_id << std::string_view(reinterpret_cast<const char *>(data.data()) + offset, n);
					offset += n;

					me->async_write_packet(std::move(packet), std::move(self));
					return;
				}

				self.complete(ec, data.size());
			},
			handler);
	}

	/// \brief To send data through the channel using SSH_MSG_CHANNEL_DATA messages
	void send_data(blob &&data, message_type msg = msg_channel_data)
	{
		send_data(std::move(data), msg, [](const asio_system_ns::error_code &, std::size_t) {});
	}

	/// \brief To send data through the channel using SSH_MSG_CHANNEL_DATA messages
	void send_data(std::string &&data, message_type msg = msg_channel_data)
	{
		send_data(std::move(data), msg, [](const asio_system_ns::error_code &, std::size_t) {});
	}

  protected:
	/// \brief Constructor taking a \a connection
	channel(std::shared_ptr<basic_connection> connection)
		: m_connection(connection)
		, m_max_send_packet_size(0)
		, m_channel_open(false)
		, m_my_channel_id(0)
		, m_host_channel_id(0)
		, m_my_window_size(kWindowSize)
		, m_host_window_size(0)
		, m_eof(false)
	{
	}

	/// \brief destructor
	virtual ~channel()
	{
		if (is_open())
			close();
	}

	/// \brief The channel type to communicate to the server.
	virtual std::string channel_type() const { return "session"; }

	// low level stuff
	/// @cond
	void send_pending(const asio_system_ns::error_code &ec = {});
	void push_received();
	void check_wait();

	virtual void receive_data(const char *data, std::size_t size);
	virtual void receive_extended_data(const char *data, std::size_t size,
		uint32_t type);

	virtual void handle_channel_request(const std::string &request, ipacket &in,
		opacket &out);

  protected:
	std::shared_ptr<basic_connection> m_connection;

	uint32_t m_max_send_packet_size;
	bool m_channel_open = false;
	uint32_t m_my_channel_id;
	uint32_t m_host_channel_id;
	uint32_t m_my_window_size;
	uint32_t m_host_window_size;

	std::deque<char> m_received;
	std::deque<std::shared_ptr<detail::read_channel_op>> m_read_ops;
	std::deque<std::shared_ptr<detail::write_channel_op>> m_write_ops;
	std::deque<std::shared_ptr<detail::wait_channel_op>> m_wait_ops;
	bool m_eof;

	message_callback_type m_banner_handler;
	message_callback_type m_message_handler;
	message_callback_type m_error_handler;

  private:
	static uint32_t s_next_channel_id;

	// --------------------------------------------------------------------

	struct async_read_impl
	{
		template <typename Handler, typename MutableBufferSequence>
		void operator()(Handler &&handler, channel *ch,
			const MutableBufferSequence &buffers)
		{
			if (not ch->is_open())
				handler(error::make_error_code(error::connection_lost), 0);
			else if (buffers.size() == 0)
				handler(asio_system_ns::error_code(), 0);
			else
			{
				ch->m_read_ops.emplace_back(new detail::read_channel_handler{
					std::move(handler), ch->get_executor(), buffers });
				ch->get_executor().execute([ch]()
					{ ch->push_received(); });
			}
		}
	};

	// --------------------------------------------------------------------

	struct async_write_impl
	{
		template <typename Handler>
		void operator()(Handler &&handler, channel *ch, opacket &&packet)
		{
			if (not ch->is_open())
				handler(error::make_error_code(error::connection_lost), 0);
			else
			{
				auto size = packet.size() - sizeof(uint32_t);
				ch->m_write_ops.emplace_back(new detail::write_channel_handler(
					std::move(handler), ch->get_executor(), std::move(packet), size));
				ch->send_pending();
			}
		}
	};

	struct async_wait_impl
	{
		template <typename Handler>
		void operator()(Handler &&handler, channel *ch, wait_type type)
		{
			ch->m_wait_ops.emplace_back(new detail::wait_channel_handler(
				std::move(handler), ch->get_executor(), type));
			ch->check_wait();
		}
	};

	/// @endcond
};

// --------------------------------------------------------------------

/**
 * @brief An exec channel executes a single command at the other side
 * 
 */
class exec_channel : public channel
{
  public:
	using callback_executor_type = asio_ns::execution::any_executor<asio_ns::execution::blocking_t::never_t>;

	/**
	 * @brief Construct a new exec channel object
	 * 
	 * @tparam Handler Type of the \a handler
	 * @tparam Executor Type of the \a executor
	 * @param connection The connection to use
	 * @param cmd The command to execute
	 * @param handler The handler that will receive the result, an integer with exit code
	 * @param executor The executor for this call
	 */

	template <typename Handler, typename Executor>
	exec_channel(std::shared_ptr<basic_connection> connection,
		const std::string &cmd, Handler &&handler, Executor executor)
		: channel(connection)
		, m_command(cmd)
		, m_handler(std::move(handler))
		, m_executor(executor)
	{
	}

	/// @cond

	void opened() override;

  protected:
	void handle_channel_request(const std::string &request, ipacket &in,
		opacket &out) override;

  private:
	std::string m_command;
	std::function<void(std::string, int)> m_handler;
	callback_executor_type m_executor;

	/// @endcond
};

} // namespace pinch
