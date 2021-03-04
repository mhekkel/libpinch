//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include <pinch/pinch.hpp>
#include <pinch/error.hpp>
#include <pinch/key_exchange.hpp>

#include <boost/algorithm/string.hpp>
#include <boost/iostreams/filtering_stream.hpp>

#include <list>
#include <deque>
#include <functional>

#include <pinch/packet.hpp>
#include "pinch/crypto-engine.hpp"
#include "pinch/ssh_agent.hpp"
#include "pinch/operations.hpp"

namespace pinch
{

// --------------------------------------------------------------------

class socket_closed_exception : public exception
{
  public:
	socket_closed_exception() : exception("socket is closed") {}
};

class basic_connection;
class key_exchange;
class channel;
using channel_ptr = std::shared_ptr<channel>;
class port_forward_listener;

// --------------------------------------------------------------------

extern const std::string kSSHVersionString;

// keyboard interactive support
struct prompt
{
	std::string str;
	bool echo;
};

using keyboard_interactive_callback_type = std::function<void(const std::string &, const std::string &, const std::vector<prompt> &)>;

// bool validate_host_key(host, alg, key)
using validate_callback_type = std::function<bool(const std::string&, const std::string&, const blob&)>;

// void request_password()
using password_callback_type = std::function<void()>;

// --------------------------------------------------------------------

namespace detail
{

enum class state_type
{
	connect, start, wrote_version, reading, rekeying, authenticating
};

enum class auth_state_type
{
	none, public_key, keyboard_interactive, password, error
};

enum class connection_wait_type
{
	read, write
};

struct async_connect_impl
{
	boost::asio::streambuf& response;
	std::shared_ptr<basic_connection> conn;
	std::string user;
	password_callback_type request_password;

	state_type state = state_type::connect;
	auth_state_type auth_state = auth_state_type::none;

	std::string host_version;
	std::unique_ptr<boost::asio::streambuf> request = std::make_unique<boost::asio::streambuf>();
	std::unique_ptr<ipacket> packet = std::make_unique<ipacket>();
	std::unique_ptr<key_exchange> kex;
	std::deque<opacket> private_keys;
	blob private_key_hash;

	keyboard_interactive_callback_type m_keyboard_interactive_cb;
	int m_password_attempts = 0;

	template<typename Self>
	void operator()(Self& self, boost::system::error_code ec = {}, std::size_t bytes_transferred = 0);

	template<typename Self>
	void failed(Self& self, boost::system::error_code ec);

	void process_userauth_success(ipacket &in, opacket &out, boost::system::error_code &ec);
	void process_userauth_failure(ipacket &in, opacket &out, boost::system::error_code &ec);
	void process_userauth_banner(ipacket &in);
	void process_userauth_info_request(ipacket &in, opacket &out, boost::system::error_code &ec);
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
	wait_connection_handler(Handler&& h, const IoExecutor& io_ex, connection_wait_type type)
		: m_handler(std::forward<Handler>(h))
		, m_io_executor(io_ex)
	{
		m_type = type;
		handler_work<Handler, IoExecutor>::start(m_handler, m_io_executor);
	}

	virtual void complete(const boost::system::error_code& ec = {}, std::size_t bytes_transferred = 0) override
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

class basic_connection : public std::enable_shared_from_this<basic_connection>
{
  public:
	basic_connection(const basic_connection&) = delete;
	basic_connection& operator=(const basic_connection& ) = delete;


	/// The type of the lowest layer.
	// using lowest_layer_type = typename next_layer_type::lowest_layer_type;
	using lowest_layer_type = typename boost::asio::basic_socket<boost::asio::ip::tcp, boost::asio::executor>::lowest_layer_type;

	/// The type of the executor associated with the object.
	using executor_type = typename lowest_layer_type::executor_type;

	virtual executor_type get_executor() noexcept = 0;
	virtual lowest_layer_type& lowest_layer() = 0;
	virtual const lowest_layer_type& lowest_layer() const = 0;

	virtual void open() = 0;
	virtual bool is_open() const = 0;

	using wait_type = detail::connection_wait_type;

	virtual ~basic_connection() {}

	virtual void disconnect();

	template<typename Handler>
	auto async_wait(wait_type type, Handler&& handler)
	{
		return boost::asio::async_initiate<Handler,void(boost::system::error_code)>(
			async_wait_impl{}, handler, this, type
		);
	}

	template<typename Handler>
	auto async_write(opacket&& p, Handler&& handler)
	{
		return async_write(m_crypto_engine.get_next_request(std::move(p)), std::move(handler));
	}

	template<typename Handler>
	auto async_write(std::unique_ptr<boost::asio::streambuf> buffer, Handler&& handler)
	{
		enum { start, writing };

		return boost::asio::async_compose<Handler, void(boost::system::error_code, std::size_t)>(
			[
				buffer = std::move(buffer),
				conn = this->shared_from_this(),
				state = start
			]
			(auto& self, const boost::system::error_code& ec = {}, std::size_t bytes_received = 0) mutable
			{
				if (not ec and state == start)
				{
					state = writing;
					boost::asio::async_write(*conn, *buffer, std::move(self));
					return;
				}

				self.complete(ec, 0);
			}, handler, *this
		);
	}

	void async_write(opacket&& out)
	{
		async_write(std::move(out), [this](const boost::system::error_code& ec, std::size_t)
		{
			if (ec)
				this->handle_error(ec);
		});
	}

	void forward_agent(bool forward)
	{
		m_forward_agent = forward;
	}

	void keep_alive();

  private:

	void async_read()
	{
		boost::asio::async_read(*this, m_response, boost::asio::transfer_at_least(1),
			[
				self = this->shared_from_this()
			]
			(const boost::system::error_code &ec, size_t bytes_transferred)
			{
				self->received_data(ec);
			});
	}

  public:

	bool uses_private_key(const blob& pk_hash)
	{
		return m_private_key_hash == pk_hash;
	}

	void set_validate_callback(const validate_callback_type &cb)
	{
		m_validate_host_key_cb = cb;
	}

	void set_password_callback(const password_callback_type &cb)
	{
		m_request_password_cb = cb;
	}

	void set_keyboard_interactive_callback(const keyboard_interactive_callback_type &cb)
	{
		m_keyboard_interactive_cb = cb;
	}

	virtual bool is_connected() const
	{
		return m_auth_state == authenticated;
	}

	// callbacks to be installed by owning object
	friend struct detail::async_connect_impl;

	template<typename Handler>
	void async_connect(Handler&& handler, channel_ptr channel)
	{
		switch (m_auth_state)
		{
			case authenticated:
				assert(false);
				handler(error::make_error_code(error::protocol_error));
				// handler()
				break;

			case handshake:
				m_channels.push_back(channel);
				break;

			case none:
				m_channels.push_back(channel);
				boost::asio::async_compose<Handler, void(boost::system::error_code)>(
					detail::async_connect_impl{
						m_response, this->shared_from_this(), m_user, m_request_password_cb
					}, handler, *this
				);
		}
	}

	virtual void handle_error(const boost::system::error_code &ec);
	void reset();

	void newkeys(key_exchange& kex, boost::system::error_code &ec)
	{
		m_crypto_engine.newkeys(kex, m_auth_state == authenticated);
	}

	void userauth_success(const std::string& host_version, const blob& session_id, const blob& pk_hash);

	void open_channel(channel_ptr ch, uint32_t id);
	void close_channel(channel_ptr ch, uint32_t id);

	bool has_open_channels();

	template<typename MutableBufferSequence, typename ReadHandler>
	auto async_read_some(const MutableBufferSequence& buffers, ReadHandler&& handler)
	{
		return boost::asio::async_initiate<ReadHandler,void(boost::system::error_code,std::size_t)>(
			async_read_impl{}, handler, this, buffers
		);
	}

	template<typename ConstBufferSequence, typename WriteHandler>
	auto async_write_some(const ConstBufferSequence & buffers, WriteHandler && handler)
	{
		return boost::asio::async_initiate<WriteHandler, void(boost::system::error_code,std::size_t)>(
			async_write_impl{}, handler, this, buffers
		);
	}

  protected:

	basic_connection(const std::string& user)
		: m_user(user)
	{
		
	}

	bool receive_packet(ipacket& packet, boost::system::error_code& ec);

	void received_data(boost::system::error_code ec);

	void process_packet(ipacket &in);
	void process_newkeys(ipacket &in, opacket &out, boost::system::error_code &ec);

	void process_channel_open(ipacket &in, opacket &out);
	void process_channel(ipacket &in, opacket &out, boost::system::error_code &ec);

	void handle_banner(const std::string &message, const std::string &lang);

	std::string m_user;

	std::string m_host_version;
	blob m_session_id;

	crypto_engine m_crypto_engine;

	enum { none, handshake, authenticated } m_auth_state = none;

	int64_t m_last_io;
	blob m_private_key_hash;
	boost::asio::streambuf m_response;

	validate_callback_type m_validate_host_key_cb;
	password_callback_type m_request_password_cb;
	keyboard_interactive_callback_type m_keyboard_interactive_cb;

	std::list<channel_ptr> m_channels;
	bool m_forward_agent;
	port_forward_listener *m_port_forwarder;

	// --------------------------------------------------------------------

	struct async_read_impl
	{
		template<typename Handler, typename MutableBufferSequence>
		void operator()(Handler&& handler, basic_connection* connection, const MutableBufferSequence& buffers);
	};

	struct async_write_impl
	{
		template<typename Handler, typename ConstBufferSequence>
		void operator()(Handler&& handler, basic_connection* connection, const ConstBufferSequence& buffers);
	};

	struct async_wait_impl
	{
		template<typename Handler>
		void operator()(Handler&& handler, basic_connection* connection, wait_type type);
	};
};

// --------------------------------------------------------------------

class connection : public basic_connection
{
  public:

	template<typename Arg>
	connection(Arg&& arg, const std::string& user)
		: basic_connection(user)
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

	const next_layer_type& next_layer() const
	{
		return m_next_layer;
	}

	next_layer_type& next_layer()
	{
		return m_next_layer;
	}

	const lowest_layer_type& lowest_layer() const override
	{
		return m_next_layer.lowest_layer();
	}

	lowest_layer_type& lowest_layer() override
	{
		return m_next_layer.lowest_layer();
	}

	virtual void disconnect() override
	{
		basic_connection::disconnect();

		m_next_layer.close();
	}

	virtual void open() override
	{
		assert(false);
		// m_next_layer.open();
	}

	virtual bool is_open() const override
	{
		return m_next_layer.is_open();
	}

  private:
	boost::asio::ip::tcp::socket m_next_layer;
};

// --------------------------------------------------------------------

class proxied_connection : public basic_connection
{
  public:
	proxied_connection(std::shared_ptr<basic_connection> proxy,
						const std::string &nc_cmd,
						const std::string &user,
						const std::string &host, int16_t port = 22);

	proxied_connection(std::shared_ptr<basic_connection> proxy,
						const std::string &user,
						const std::string &host, int16_t port = 22);

	~proxied_connection();

	/// The type of the next layer.
	using next_layer_type = channel;

	virtual executor_type get_executor() noexcept override;

	const next_layer_type& next_layer() const
	{
		return *m_channel;
	}

	next_layer_type& next_layer()
	{
		return *m_channel;
	}

	const lowest_layer_type& lowest_layer() const override;

	lowest_layer_type& lowest_layer() override;

	virtual void disconnect() override;

	virtual void set_validate_callback(const validate_callback_type &cb);

	// virtual std::shared_ptr<basic_connection> get_proxy() const
	// {
	// 	return m_proxy;
	// }

	virtual void open() override;
	virtual bool is_open() const override;

  protected:

	virtual bool validate_host_key(const std::string &pk_alg, const blob &host_key);

  private:
	friend async_wait_impl;

	void do_wait(std::unique_ptr<detail::wait_connection_op> op);

	std::shared_ptr<basic_connection> m_proxy;
	std::shared_ptr<channel> m_channel;
	std::string m_host;
};

// --------------------------------------------------------------------

template<typename Handler, typename MutableBufferSequence>
void basic_connection::async_read_impl::operator()(Handler&& handler, basic_connection* conn, const MutableBufferSequence& buffers)
{
	auto c = dynamic_cast<connection*>(conn);
	if (c)
		boost::asio::async_read(c->next_layer(), buffers, boost::asio::transfer_at_least(1), std::move(handler));
	else
	{
		auto pc = dynamic_cast<proxied_connection*>(conn);
		if (pc)
			boost::asio::async_read(pc->next_layer(), buffers, boost::asio::transfer_at_least(1), std::move(handler));
	}
}

template<typename Handler, typename ConstBufferSequence>
void basic_connection::async_write_impl::operator()(Handler&& handler, basic_connection* conn, const ConstBufferSequence& buffers)
{
	auto c = dynamic_cast<connection*>(conn);
	if (c)
		boost::asio::async_write(c->next_layer(), buffers, std::move(handler));
	else
	{
		auto pc = dynamic_cast<proxied_connection*>(conn);
		if (pc)
			boost::asio::async_write(pc->next_layer(), buffers, std::move(handler));
	}
}

template<typename Handler>
void basic_connection::async_wait_impl::operator()(Handler&& handler, basic_connection* conn, basic_connection::wait_type type)
{
	auto c = dynamic_cast<connection*>(conn);
	auto pc = dynamic_cast<proxied_connection*>(conn);

	assert(!c != !pc);

	switch (type)
	{
		case wait_type::read:
			if (c)
				c->next_layer().async_wait(boost::asio::socket_base::wait_read, std::move(handler));
			else
				pc->do_wait(std::unique_ptr<detail::wait_connection_op>(new detail::wait_connection_handler(std::move(handler), pc->get_executor(), type)));
			break;
		
		case wait_type::write:
			if (c)
				c->next_layer().async_wait(boost::asio::socket_base::wait_write, std::move(handler));
			else
				pc->do_wait(std::unique_ptr<detail::wait_connection_op>(new detail::wait_connection_handler(std::move(handler), pc->get_executor(), type)));
			break;
		
		default:
			assert(false);
	}
}

// --------------------------------------------------------------------

namespace detail
{

template<typename Self>
void async_connect_impl::operator()(Self& self, boost::system::error_code ec, std::size_t bytes_transferred)
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
				failed(self, error::make_error_code(error::protocol_version_not_supported));
				return;
			}

			state = state_type::rekeying;
			kex = std::make_unique<key_exchange>(host_version);

			conn->async_write(kex->init());
			
			boost::asio::async_read(*conn, response, boost::asio::transfer_at_least(8), std::move(self));
			return;
		}

		case state_type::rekeying:
		{
			for (;;)
			{
				if (not conn->receive_packet(*packet, ec) and not ec)
				{
					boost::asio::async_read(*conn, response, boost::asio::transfer_at_least(1), std::move(self));
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
					for (auto& pk: ssh_agent::instance())
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
					boost::asio::async_read(*conn, response, boost::asio::transfer_at_least(1), std::move(self));
					return;
				}

				auto& in = *packet;
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
						conn->userauth_success(host_version, kex->session_id(), private_key_hash);
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

template<typename Self>
void async_connect_impl::failed(Self& self, boost::system::error_code ec)
{
	conn->disconnect();
	self.complete(ec);
}

} // namespace detail

}
