//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include <pinch/pinch.hpp>

#include <cassert>

#include <list>
#include <string>
#include <deque>
#include <numeric>
#include <future>

#include <boost/type_traits.hpp>
#include <boost/asio.hpp>
#include <boost/asio/use_future.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/thread/condition.hpp>

#include <pinch/error.hpp>
#include <pinch/packet.hpp>
#include <pinch/connection.hpp>
#include <pinch/operations.hpp>

namespace pinch
{

class connection_base;

const uint32_t
	kMaxPacketSize = 0x8000,
	kWindowSize = 4 * kMaxPacketSize;

// --------------------------------------------------------------------

namespace detail
{

class open_channel_op : public operation
{
  public:
	boost::system::error_code m_ec;
};

template <typename Handler, typename IoExecutor>
class open_channel_handler : public open_channel_op
{
  public:
	open_channel_handler(Handler&& h, const IoExecutor& io_ex)
		: m_handler(std::move(h))
		, m_io_executor(io_ex)
	{
		handler_work<Handler, IoExecutor>::start(m_handler, m_io_executor);
	}

	virtual void complete(const boost::system::error_code& ec, std::size_t bytes_transferred = 0) override
	{
		handler_work<Handler, IoExecutor> w(m_handler, m_io_executor);

		binder1<Handler, boost::system::error_code> handler(m_handler, m_ec);

		w.complete(handler, handler.m_handler);
  }

  private:
	Handler m_handler;
	IoExecutor m_io_executor;
};

}

// --------------------------------------------------------------------

class channel : public std::enable_shared_from_this<channel>
{
	public:

	using connection_type = basic_connection<boost::asio::ip::tcp::socket>;

	/// The type of the next layer.
	using next_layer_type = connection_type;

	/// The type of the lowest layer.
	using lowest_layer_type = typename boost::asio::ip::tcp::socket;

	/// The type of the executor associated with the object.
	using executor_type = typename lowest_layer_type::executor_type;

	executor_type get_executor() noexcept
	{
		return m_connection->get_executor();
	}

	const next_layer_type& next_layer() const;

	next_layer_type& next_layer();

	const lowest_layer_type& lowest_layer() const;

	lowest_layer_type& lowest_layer();

	struct environment_variable
	{
		std::string name;
		std::string value;
	};

	typedef std::list<environment_variable> environment;

	template<typename Handler>
	void async_open(Handler&& handler)
	{
		enum { start, open };

		using handler_type = detail::open_channel_handler<Handler, executor_type>;

		assert(m_open_handler == nullptr);
		m_open_handler.reset(new handler_type(std::move(handler), get_executor()));

		if (m_connection->is_connected())
			this->open();
		else
			static_cast<basic_connection<boost::asio::ip::tcp::socket>*>(m_connection.get())->async_connect([self = shared_from_this()]
				(const boost::system::error_code& ec)
				{
					if (ec)
					{
						self->m_open_handler->complete(ec, 0);
						self->m_open_handler.reset();
					}
					else
						self->open();
				}
			);
	}

	void open();
	void close();
	// void disconnect(bool disconnectProxy = false);

	virtual void fill_open_opacket(opacket& out);

	virtual void opened();
	virtual void closed();
	virtual void end_of_file();

	// void keep_alive();

	virtual void succeeded(); // the request succeeded

	// std::string get_connection_parameters(direction dir) const;
	// std::string get_key_exchange_algoritm() const;

	void open_pty(uint32_t width, uint32_t height,
				  const std::string& terminal_type,
				  bool forward_agent, bool forward_x11,
				  const environment& env);

	void send_request_and_command(const std::string& request,
								  const std::string& command);

	void send_signal(const std::string& inSignal);

	uint32_t my_channel_id() const { return m_my_channel_id; }
	bool is_open() const { return m_channel_open; }

	typedef std::function<void(const std::string &, const std::string &)> message_callback_type;

	void set_message_callbacks(message_callback_type banner_handler, message_callback_type message_handler, message_callback_type error_handler)
	{
		m_banner_handler = banner_handler;
		m_message_handler = message_handler;
		m_error_handler = error_handler;
	}

	virtual void banner(const std::string& msg, const std::string& lang);
	virtual void message(const std::string& msg, const std::string& lang);
	virtual void error(const std::string& msg, const std::string& lang);

	// virtual void init(ipacket& in, opacket& out);
	virtual void process(ipacket& in);

	// // boost::asio AsyncWriteStream interface
	// boost::asio::io_service& get_io_service();

	// template <class Handler>
	// struct bound_handler
	// {
	// 	bound_handler(const bound_handler &) = default;

	// 	bound_handler(bound_handler&& rhs)
	// 		: m_handler(std::move(rhs.m_handler)), m_ec(rhs.m_ec), m_transferred(rhs.m_transferred)
	// 	{
	// 	}

	// 	bound_handler(Handler&& handler, const boost::system::error_code& ec, std::size_t s)
	// 		: m_handler(std::move(handler)), m_ec(ec), m_transferred(s)
	// 	{
	// 	}

	// 	virtual void operator()()
	// 	{
	// 		m_handler(m_ec, m_transferred);
	// 	}

	// 	Handler m_handler;
	// 	boost::system::error_code m_ec;
	// 	std::size_t m_transferred;
	// };

	// struct basic_io_op
	// {
	// 	virtual ~basic_io_op() {}
	// 	virtual void error(const boost::system::error_code& ec) = 0;
	// };

	// struct basic_write_op : public basic_io_op
	// {
	// 	basic_write_op(std::list<opacket>&& p)
	// 		: m_packets(std::move(p))
	// 	{
	// 	}

	// 	basic_write_op(opacket&& p)
	// 	{
	// 		m_packets.push_back(std::move(p));
	// 	}

	// 	virtual void written(const boost::system::error_code& ec, std::size_t bytes_transferred,
	// 						 boost::asio::io_service& io_service) = 0;

	// 	std::list<opacket> m_packets;
	// };

	// template <typename Handler>
	// struct write_op : public basic_write_op
	// {
	// 	write_op(std::list<opacket>&& p, Handler&& h)
	// 		: basic_write_op(std::move(p)), m_handler(std::move(h))
	// 	{
	// 	}

	// 	write_op(opacket&& p, Handler&& h)
	// 		: basic_write_op(std::move(p)), m_handler(std::move(h))
	// 	{
	// 	}

	// 	virtual void written(const boost::system::error_code& ec, std::size_t bytes_transferred,
	// 						 boost::asio::io_service& io_service)
	// 	{
	// 		std::size_t n = 0;
	// 		n = std::accumulate(m_packets.begin(), m_packets.end(), n,
	// 							[](std::size_t c, opacket& p) -> uint32_t { return c + p.size(); });

	// 		io_service.post(bound_handler<Handler>(std::move(m_handler), ec, n));
	// 	}

	// 	virtual void error(const boost::system::error_code& ec)
	// 	{
	// 		m_handler(ec, 0);
	// 	}

	// 	Handler m_handler;
	// };

	// template <typename Handler>
	// void make_write_op(std::list<opacket>&& p, Handler&& h)
	// {
	// 	m_pending.push_back(new write_op<Handler>(std::move(p), std::move(h)));
	// 	send_pending();
	// }

	// template <typename Handler>
	// void make_write_op(opacket&& p, Handler&& h)
	// {
	// 	m_pending.push_back(new write_op<Handler>(std::move(p), std::move(h)));
	// 	send_pending();
	// }

	// template <typename ConstBufferSequence, typename Handler>
	// void async_write_some(const ConstBufferSequence& buffers, Handler&& handler)
	// {
	// 	typedef ConstBufferSequence buffer_type;
	// 	boost::asio::io_service& io_service(get_io_service());

	// 	size_t n = boost::asio::buffer_size(buffers);

	// 	if (not is_open())
	// 		io_service.post(bound_handler<Handler>(std::move(handler),
	// 											   error::make_error_code(error::connection_lost), 0));
	// 	else if (n == 0)
	// 		io_service.post(bound_handler<Handler>(std::move(handler), boost::system::error_code(), 0));
	// 	else
	// 	{
	// 		std::list<opacket> packets;

	// 		for (typename buffer_type::const_iterator buffer = buffers.begin(); buffer != buffers.end(); ++buffer)
	// 		{
	// 			const char *b = boost::asio::buffer_cast<const char *>(*buffer);
	// 			const char *e = b + n;

	// 			while (b != e)
	// 			{
	// 				std::size_t k = e - b;
	// 				if (k > m_max_send_packet_size)
	// 					k = m_max_send_packet_size;

	// 				packets.push_back(opacket(msg_channel_data) << m_host_channel_id << std::make_pair(b, k));

	// 				b += k;
	// 			}
	// 		}

	// 		make_write_op(std::move(packets), std::move(handler));
	// 	}
	// }

	// template <typename MutableBufferSequence>
	// std::size_t write_some(const MutableBufferSequence& buffers)
	// {
	// 	boost::system::error_code ec;
	// 	std::size_t s = write_some(buffers, ec);
	// 	if (ec)
	// 		throw std::system_error(ec);
	// 	return s;
	// }

	// template <typename MutableBufferSequence>
	// std::size_t write_some(const MutableBufferSequence& buffers, boost::system::error_code& ec)
	// {
	// 	std::size_t s = 0;
	// 	// boost::asio::io_service& io_service(get_io_service());

	// 	size_t n = boost::asio::buffer_size(buffers);

	// 	if (not is_open())
	// 		ec = error::make_error_code(error::connection_lost);
	// 	else if (n == 0)
	// 		ec = boost::system::error_code();
	// 	else
	// 	{
	// 		boost::mutex mtx;
	// 		boost::mutex::scoped_lock lock(mtx);
	// 		boost::condition c;

	// 		async_write_some(buffers, [&](const boost::system::error_code& ec_, std::size_t bytes_transferred) {
	// 			ec = ec_;
	// 			s = bytes_transferred;
	// 			c.notify_one();
	// 		});

	// 		c.wait(lock);
	// 	}

	// 	return s;
	// }

	// struct basic_read_op : public basic_io_op
	// {
	// 	typedef std::deque<char>::iterator iterator;

	// 	virtual iterator receive_and_post(iterator begin, iterator end, boost::asio::io_service& io_service) = 0;
	// };

	// template <class MutableBufferSequence, class Handler>
	// struct read_op : public basic_read_op
	// {
	// 	read_op(read_op&& rhs)
	// 		: m_buffer(std::move(rhs.m_buffer)), m_handler(std::move(rhs.m_handler)) {}

	// 	read_op(const MutableBufferSequence& buffer, Handler&& handler)
	// 		: m_buffer(buffer), m_handler(std::move(handler)) {}

	// 	virtual iterator receive_and_post(iterator begin, iterator end, boost::asio::io_service& io_service)
	// 	{
	// 		std::size_t n = end - begin;
	// 		if (n > boost::asio::buffer_size(m_buffer))
	// 			n = boost::asio::buffer_size(m_buffer);
	// 		char *ptr = boost::asio::buffer_cast<char *>(m_buffer);

	// 		end = begin + n;
	// 		std::copy(begin, end, ptr);

	// 		io_service.post(bound_handler<Handler>(std::move(m_handler), boost::system::error_code(), n));

	// 		return end;
	// 	}

	// 	virtual void error(const boost::system::error_code& ec)
	// 	{
	// 		m_handler(ec, 0);
	// 	}

	// 	MutableBufferSequence m_buffer;
	// 	Handler m_handler;
	// };

	// template <typename MutableBufferSequence>
	// std::size_t read_some(const MutableBufferSequence& buffers)
	// {
	// 	boost::system::error_code ec;
	// 	std::size_t s = read_some(buffers, ec);
	// 	if (ec)
	// 		throw std::system_error(ec);
	// 	return s;
	// }

	// template <typename MutableBufferSequence>
	// std::size_t read_some(const MutableBufferSequence& buffers, boost::system::error_code& ec)
	// {
	// 	size_t s = 0;
	// 	// boost::asio::io_service& io_service(get_io_service());

	// 	if (not is_open())
	// 		ec = error::make_error_code(error::connection_lost);
	// 	else if (boost::asio::buffer_size(buffers) == 0)
	// 		ec = boost::system::error_code();
	// 	else
	// 	{
	// 		boost::mutex mtx;
	// 		boost::mutex::scoped_lock lock(mtx);
	// 		boost::condition c;

	// 		//async_read_some(buffers, [&](const boost::system::error_code& ec_, std::size_t bytes_transferred_)

	// 		auto handler = [&](const boost::system::error_code& ec_, std::size_t bytes_transferred_) {
	// 			ec = ec_;
	// 			s = bytes_transferred_;
	// 			c.notify_one();
	// 		};

	// 		m_read_ops.push_back(new read_op<MutableBufferSequence, decltype(handler)>(buffers, std::move(handler)));

	// 		if (not m_received.empty())
	// 			push_received();

	// 		c.wait(lock);
	// 	}
	// 	return s;
	// }

	// // To send data through the channel using SSH_MSG_CHANNEL_DATA messages
	// template <typename Handler>
	// void send_data(const std::string& data, Handler&& handler)
	// {
	// 	opacket out = opacket(msg_channel_data) << m_host_channel_id << data;
	// 	make_write_op(std::move(out), std::move(handler));
	// }

	// void send_data(const opacket& data)
	// {
	// 	opacket out = opacket(msg_channel_data) << m_host_channel_id << data;
	// 	make_write_op(std::move(out),
	// 				  [](const boost::system::error_code& ec, std::size_t bytes_transferred) {});
	// }

	// template <typename Handler>
	// void send_data(const char *data, size_t size, Handler&& handler)
	// {
	// 	opacket out = opacket(msg_channel_data) << m_host_channel_id << std::make_pair(data, size);
	// 	make_write_op(std::move(out), std::move(handler));
	// }

	// template <typename Handler>
	// void send_data(opacket& data, Handler&& handler)
	// {
	// 	make_write_op(
	// 		opacket(msg_channel_data) << m_host_channel_id << data,
	// 		std::move(handler));
	// }

	// template <typename Handler>
	// void send_extended_data(opacket& data, uint32_t type, Handler&& handler)
	// {
	// 	make_write_op(
	// 		m_connection,
	// 		opacket(msg_channel_extended_data) << m_host_channel_id << type << data,
	// 		std::move(handler));
	// }

//   protected:
	
	channel(std::shared_ptr<connection_base> connection)
		: m_connection(connection)
		, m_max_send_packet_size(0)
		, m_channel_open(false)
		, m_send_pending(false)
		, m_my_channel_id(0)
		, m_host_channel_id(0)
		, m_my_window_size(kWindowSize)
		, m_host_window_size(0)
		, m_eof(false)
	{
	}

	virtual ~channel()
	{
		// if (is_open())
		// 	close();
	}

	virtual std::string
	channel_type() const { return "session"; }

	virtual void setup(ipacket& in);

	// low level
	void send_pending();
	void push_received();

	virtual void receive_data(const char *data, std::size_t size);
	virtual void receive_extended_data(const char *data, std::size_t size, uint32_t type);

	virtual void handle_channel_request(const std::string& request, ipacket& in, opacket& out);

  protected:

	std::shared_ptr<connection_base> m_connection;
	std::unique_ptr<detail::open_channel_op> m_open_handler;

	uint32_t m_max_send_packet_size;
	bool m_channel_open = false, m_send_pending = false;
	uint32_t m_my_channel_id;
	uint32_t m_host_channel_id;
	uint32_t m_my_window_size;
	uint32_t m_host_window_size;

	// std::deque<basic_write_op *> m_pending;
	std::deque<char> m_received;
	// std::deque<basic_read_op *> m_read_ops;
	bool m_eof;

	message_callback_type m_banner_handler;
	message_callback_type m_message_handler;
	message_callback_type m_error_handler;

  private:
	static uint32_t s_next_channel_id;
};

// // --------------------------------------------------------------------

// class exec_channel : public channel
// {
// public:
// 	struct basic_result_handler
// 	{
// 		virtual ~basic_result_handler() {}
// 		virtual void post_result(const std::string& message, int32_t result_code) = 0;
// 	};

// 	template <typename Handler>
// 	struct result_handler : public basic_result_handler
// 	{
// 		result_handler(Handler&& handler)
// 			: m_handler(std::move(handler)) {}

// 		virtual void post_result(const std::string& message, int32_t result_code)
// 		{
// 			m_handler(message, result_code);
// 		}

// 		Handler m_handler;
// 	};

// 	template <typename Handler>
// 	exec_channel(std::shared_ptr<connection_base> connection,
// 				 const std::string& cmd, Handler&& handler)
// 		: channel(connection), m_command(cmd), m_handler(new result_handler<Handler>(std::move(handler)))
// 	{
// 	}

// 	~exec_channel()
// 	{
// 		delete m_handler;
// 	}

// 	virtual void opened();

// protected:
// 	virtual void handle_channel_request(const std::string& request, ipacket& in, opacket& out);

// private:
// 	std::string m_command;
// 	basic_result_handler *m_handler;
// };

} // namespace pinch
