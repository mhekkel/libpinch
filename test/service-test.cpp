//#define BOOST_ASIO_ENABLE_HANDLER_TRACKING

#include <boost/asio.hpp>

#include <iostream>
#include <deque>

#include <type_traits>

#include <boost/algorithm/string.hpp>
#include <boost/iostreams/filtering_stream.hpp>

#include "assh/connection.hpp"
#include "assh/connection_pool.hpp"
#include "assh/channel.hpp"
#include "assh/terminal_channel.hpp"
#include "assh/ssh_agent.hpp"
#include "assh/crypto-engine.hpp"

namespace ba = boost::algorithm;
namespace io = boost::iostreams;

namespace assh
{

template<typename> class connection2;

// keyboard interactive support
struct prompt
{
	std::string str;
	bool echo;
};
typedef std::function<void(const std::string &, const std::string &, const std::vector<prompt> &)> keyboard_interactive_callback_type;

namespace detail
{




enum class auth_state_type
{
	none,
	connecting,
	public_key,
	keyboard_interactive,
	password,
	connected,
	authenticated
};

template<typename Stream>
struct async_connect_impl
{
	using socket_type = Stream;

	socket_type& socket;
	boost::asio::streambuf& response;
	std::shared_ptr<connection2<Stream>> conn;
	std::string user;

	enum state_type { start, wrote_version, reading, rekeying, authenticating } state = start;
	auth_state_type auth_state = auth_state_type::none;

	std::string host_version;
	std::unique_ptr<boost::asio::streambuf> request = std::make_unique<boost::asio::streambuf>();
	std::unique_ptr<ipacket> packet = std::make_unique<ipacket>();
	std::unique_ptr<key_exchange> kex;
	std::deque<opacket> private_keys;
	std::vector<uint8_t> private_key_hash;

	keyboard_interactive_callback_type m_request_password_cb, m_keyboard_interactive_cb;
	int m_password_attempts = 0;

	template<typename Self>
	void operator()(Self& self, boost::system::error_code ec = {}, std::size_t bytes_transferred = 0);

	void process_userauth_success(ipacket &in, opacket &out, boost::system::error_code &ec);
	void process_userauth_failure(ipacket &in, opacket &out, boost::system::error_code &ec);
	void process_userauth_banner(ipacket &in, opacket &out, boost::system::error_code &ec);
	void process_userauth_info_request(ipacket &in, opacket &out, boost::system::error_code &ec);
};


template<typename Stream>
template<typename Self>
void async_connect_impl<Stream>::operator()(Self& self, boost::system::error_code ec, std::size_t bytes_transferred)
{
	if (not ec)
	{
		switch (state)
		{
			case start:
			{
				std::ostream out(request.get());
				out << kSSHVersionString << "\r\n";
				state = wrote_version;
				boost::asio::async_write(socket, *request, std::move(self));
				return;
			}
			
			case wrote_version:
				state = reading;
				boost::asio::async_read_until(socket, response, "\n", std::move(self));
				return;

			case reading:
			{
				std::istream response_stream(&response);
				std::getline(response_stream, host_version);
				ba::trim_right(host_version);

				if (not ba::starts_with(host_version, "SSH-2.0"))
				{
					self.complete(error::make_error_code(error::protocol_version_not_supported));
					return;
				}

				state = rekeying;
				kex = std::make_unique<key_exchange>(host_version);

				conn->async_write(kex->init());
				
				boost::asio::async_read(socket, response, boost::asio::transfer_at_least(8), std::move(self));
				return;
			}

			case rekeying:
			{
				for (;;)
				{
					if (not conn->receive_packet(*packet, ec) and not ec)
					{
						boost::asio::async_read(socket, response, boost::asio::transfer_at_least(1), std::move(self));
						return;
					}

					opacket out;
					if (*packet == msg_newkeys)
					{
						conn->newkeys(*kex, ec);

						if (ec)
						{
							self.complete(ec);
							return;
						}

						state = authenticating;

						out = msg_service_request;
						out << "ssh-userauth";

						// we might not be known yet
						// ssh_agent::instance().register_connection(conn);

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
						self.complete(error::make_error_code(error::key_exchange_failed));
						return;
					}

					if (ec)
					{
						self.complete(ec);
						return;
					}

					if (out)
						conn->async_write(std::move(out));
					
					packet->clear();
				}
			}

			case authenticating:
			{
				if (not conn->receive_packet(*packet, ec) and not ec)
				{
					boost::asio::async_read(socket, response, boost::asio::transfer_at_least(1), std::move(self));
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
std::cerr << msg << '\t' << lang << std::endl;
						break;
					}

					case msg_userauth_info_request:
						process_userauth_info_request(in, out, ec);
						break;

					case msg_userauth_success:
						conn->userauth_success(host_version, kex->session_id());
						self.complete({});
						return;
				}

				if (out)
					conn->async_write(std::move(out));
				
				if (ec)
					self.complete(ec);
				else
				{
					packet->clear();
					boost::asio::async_read(socket, response, boost::asio::transfer_at_least(1), std::move(self));
				}

				return;
			}
		}
	}

	self.complete(ec);
}

template<typename Stream>
void async_connect_impl<Stream>::async_connect_impl::process_userauth_failure(ipacket &in, opacket &out, boost::system::error_code &ec)
{
	std::string s;
	bool partial;

	in >> s >> partial;

	private_key_hash.clear();

	if (choose_protocol(s, "publickey") == "publickey" and not private_keys.empty())
	{
		out = opacket(msg_userauth_request)
				<< user << "ssh-connection"
				<< "publickey" << false
				<< "ssh-rsa" << private_keys.front();
		private_keys.pop_front();
		auth_state = auth_state_type::public_key;
	}
	else if (choose_protocol(s, "keyboard-interactive") == "keyboard-interactive" and m_keyboard_interactive_cb and ++m_password_attempts <= 3)
	{
		out = opacket(msg_userauth_request)
				<< user << "ssh-connection"
				<< "keyboard-interactive"
				<< "en"
				<< "";
		auth_state = auth_state_type::keyboard_interactive;
	}
	else if (choose_protocol(s, "password") == "password" and m_request_password_cb and ++m_password_attempts <= 3)
		assert(false);
		// m_request_password_cb();
	else
		ec = error::make_error_code(error::no_more_auth_methods_available);
}

template<typename Stream>
void async_connect_impl<Stream>::process_userauth_banner(ipacket &in, opacket &out, boost::system::error_code &ec)
{
	std::string msg, lang;
	in >> msg >> lang;

std::cerr << msg << '\t' << lang << std::endl;

	// for (auto h : m_connect_handlers)
	// 	h->handle_banner(msg, lang);
}

template<typename Stream>
void async_connect_impl<Stream>::process_userauth_info_request(ipacket &in, opacket &out, boost::system::error_code &ec)
{
	switch (auth_state)
	{
		case auth_state_type::public_key:
		{
			out = msg_userauth_request;

			std::string alg;
			ipacket blob;

			in >> alg >> blob;

			out << user << "ssh-connection"
				<< "publickey" << true << "ssh-rsa" << blob;

			opacket session_id;
			session_id << kex->session_id();

			ssh_private_key pk(ssh_agent::instance().get_key(blob));

			out << pk.sign(session_id, out);

			// store the hash for this private key
			private_key_hash = pk.get_hash();
			break;
		}
		case auth_state_type::keyboard_interactive:
		{
			std::string name, instruction, language;
			int32_t numPrompts = 0;

			in >> name >> instruction >> language >> numPrompts;

			if (numPrompts == 0)
			{
				out = msg_userauth_info_response;
				out << numPrompts;
			}
			else
			{
				std::vector<prompt> prompts(numPrompts);

				for (auto& p : prompts)
					in >> p.str >> p.echo;

				if (prompts.empty())
					prompts.push_back({ "iets", true });

				m_keyboard_interactive_cb(name, language, prompts);
			}
			break;
		}
		default:;
	}
}


}




template<typename Stream>
class connection2 : public std::enable_shared_from_this<connection2<Stream>>
{
  public:

	template<typename Arg>
	connection2(Arg&& arg, const std::string& user)
		: m_next_layer(std::forward<Arg>(arg))
		, m_user(user)
	{
		reset();
	}

	virtual ~connection2()
	{

	}

	/// The type of the next layer.
	using next_layer_type = std::remove_reference_t<Stream>;

	/// The type of the lowest layer.
	using lowest_layer_type = typename next_layer_type::lowest_layer_type;

	/// The type of the executor associated with the object.
	using executor_type = typename lowest_layer_type::executor_type;

	executor_type get_executor() noexcept
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

	const lowest_layer_type& lowest_layer() const
	{
		return m_next_layer.lowest_layer();
	}

	lowest_layer_type& lowest_layer()
	{
		return m_next_layer.lowest_layer();
	}

	// configure before connecting
	void set_algorithm(algorithm alg, direction dir, const std::string &preferred);

	// callbacks to be installed by owning object

	// bool validate_host_key(host, alg, key)
	using validate_callback_type = std::function<bool(const std::string&, const std::string&, const std::vector<uint8_t>&)>;

	// void request_password()
	typedef std::function<void()> password_callback_type;

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

	using async_connect_impl = detail::async_connect_impl<next_layer_type>;
	friend async_connect_impl;

	template<typename Handler>
	auto async_handshake(Handler&& handler)
	{
		return boost::asio::async_compose<Handler, void(boost::system::error_code)>(
			async_connect_impl{
				m_next_layer, m_response, this->shared_from_this(), m_user
			}, handler, m_next_layer
		);
	}

	void rekey()
	{
		assert(false);
		// m_key_exchange.reset(new key_exchange(m_host_version, m_session_id));
		// async_write(m_key_exchange->init());
	}

	void async_write(opacket&& out)
	{
		async_write(std::move(out), [this](const boost::system::error_code& ec, std::size_t)
		{
			if (ec)
				this->handle_error(ec);
		});
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
				&socket = m_next_layer,
				buffer = std::move(buffer),
				conn = this->shared_from_this(),
				state = start
			]
			(auto& self, const boost::system::error_code& ec = {}, std::size_t bytes_received = 0) mutable
			{
				if (not ec and state == start)
				{
					state = writing;
					boost::asio::async_write(socket, *buffer, std::move(self));
					return;
				}

				self.complete(ec, 0);
			}, handler, m_next_layer
		);
	}

  protected:

	virtual void disconnect()
	{
		reset();

		// // copy the list since calling Close will change it
		// std::list<channel_ptr> channels(m_channels);
		// std::for_each(channels.begin(), channels.end(), [](channel_ptr c) { c->close(); });

		m_next_layer.close();
	}

	virtual void handle_error(const boost::system::error_code &ec)
	{
		if (ec)
		{
			// std::for_each(m_channels.begin(), m_channels.end(), [&ec](channel_ptr ch) { ch->error(ec.message(), ""); });
			disconnect();

			m_auth_state = detail::auth_state_type::connected;
			// handle_connect_result(ec);
		}
	}

	template<typename Handler>
	auto async_read_packet(Handler&& handler);

  private:

	bool receive_packet(ipacket& packet, boost::system::error_code& ec);

	void received_data(const boost::system::error_code& ec);

	void process_packet(ipacket &in);
	void process_newkeys(ipacket &in, opacket &out, boost::system::error_code &ec);
	void userauth_success(const std::string& host_version, const std::vector<uint8_t>& session_id);

	void process_channel_open(ipacket &in, opacket &out);
	void process_channel(ipacket &in, opacket &out, boost::system::error_code &ec);

	void newkeys(key_exchange& kex, boost::system::error_code &ec);

	void async_read()
	{
		uint32_t at_least = m_iblocksize;
		if (m_response.size() >= m_iblocksize)
		{
			// if we arrive here, we might have read a block, but not the digest?
			// call readsome with 0 as at-least, that will return something we hope.
			at_least = 1;
		}
		else
			at_least -= m_response.size();

		boost::asio::async_read(m_next_layer, m_response, boost::asio::transfer_at_least(at_least),
			[
				self = this->shared_from_this()
			]
			(const boost::system::error_code &ec, size_t bytes_transferred)
			{
				self->received_data(ec);
			});
	}

	void reset()
	{
		m_auth_state = detail::auth_state_type::none;
		m_private_key_hash.clear();
		m_session_id.clear();
		m_packet.clear();
		m_crypto_engine.reset();
		m_last_io = 0;
	}

	Stream m_next_layer;
	std::string m_user;

	detail::auth_state_type m_auth_state = detail::auth_state_type::none;
	std::string m_host_version;
	std::vector<uint8_t> m_session_id;

	crypto_engine m_crypto_engine;

	// connect_handler_list m_connect_handlers;

	int64_t m_last_io;
	// uint32_t m_password_attempts;
	std::vector<uint8_t> m_private_key_hash;
	ipacket m_packet;
	uint32_t m_iblocksize, m_oblocksize;
	boost::asio::streambuf m_response;

	validate_callback_type m_validate_host_key_cb;
	password_callback_type m_request_password_cb;
	keyboard_interactive_callback_type m_keyboard_interactive_cb;

	std::list<channel_ptr> m_channels;
	bool m_forward_agent;
	port_forward_listener *m_port_forwarder;
};

template<typename Stream>
template<typename Handler>
auto connection2<Stream>::async_read_packet(Handler&& handler)
{
	auto packet = std::make_unique<ipacket>();

	return boost::asio::async_compose<Handler, void(boost::system::error_code)>(
		[
			&socket = this->m_next_layer,
			conn = this->shared_from_this(),
			packet = std::move(packet),
			this
		]
		(auto& self, const boost::system::error_code& ec = {}, std::size_t bytes_transferred = 0) mutable
		{
			if (ec)
			{
				self.complete(ec, {});
				return;
			}

			

			uint32_t at_least = m_iblocksize;
			if (m_response.size() >= m_iblocksize)
			{
				// if we arrive here, we might have read a block, but not the digest?
				// call readsome with 0 as at-least, that will return something we hope.
				at_least = 1;
			}
			else
				at_least -= m_response.size();

			boost::asio::async_read(socket, m_response, boost::asio::transfer_at_least(at_least), std::move(self));
		}
	);
}



// the read loop, this routine keeps calling itself until an error condition is met
template<typename Stream>
void connection2<Stream>::received_data(const boost::system::error_code& ec)
{
	if (ec)
	{
		handle_error(ec);
		return;
	}

	// don't process data at all if we're no longer willing
	if (m_auth_state == detail::auth_state_type::none)
		return;

	try
	{
		auto p = m_crypto_engine.get_next_packet(m_response, ec);

		if (ec)
			handle_error(ec);
		else if (p)
			process_packet(*p);

		async_read();
	}
	catch (...)
	{
		try
		{
			disconnect();
		}
		catch (...)
		{
		}
		throw;
	}
}

template<typename Stream>
void connection2<Stream>::process_packet(ipacket& in)
{
	// update time for keep alive
	struct timeval tv;
	gettimeofday(&tv, nullptr);
	m_last_io = tv.tv_sec;

	opacket out;
	boost::system::error_code ec;

	switch ((message_type)in)
	{
		case msg_disconnect:
		{
			uint32_t reasonCode;
			in >> reasonCode;
			handle_error(error::make_error_code(error::disconnect_errors(reasonCode)));
			break;
		}

		case msg_ignore:
		case msg_unimplemented:
		case msg_debug:
			break;

		case msg_service_request:
			disconnect();
			break;

		// channel
		case msg_channel_open:
			if (m_auth_state == detail::auth_state_type::authenticated)
				process_channel_open(in, out);
			break;
		case msg_channel_open_confirmation:
		case msg_channel_open_failure:
		case msg_channel_window_adjust:
		case msg_channel_data:
		case msg_channel_extended_data:
		case msg_channel_eof:
		case msg_channel_close:
		case msg_channel_request:
		case msg_channel_success:
		case msg_channel_failure:
			if (m_auth_state == detail::auth_state_type::authenticated)
				process_channel(in, out, ec);
			break;

		default:
		{
			opacket out(msg_unimplemented);
			out << m_crypto_engine.get_next_out_seq_nr();
			async_write(std::move(out));
			break;
		}
	}

	if (ec)
		// handle_connect_result(ec);
		handle_error(ec);

	if (not out.empty())
		async_write(std::move(out));
}

template<typename Stream>
bool connection2<Stream>::receive_packet(ipacket& packet, boost::system::error_code& ec)
{
	bool result = false;
	ec = {};

	auto p = m_crypto_engine.get_next_packet(m_response, ec);

	if (not ec and p)
	{
		result = true;
		std::swap(packet, *p);

		switch ((message_type)packet)
		{
			case msg_disconnect:
				m_next_layer.close();
				break;

			case msg_service_request:
				disconnect();
				break;

			case msg_ignore:
			case msg_unimplemented:
			case msg_debug:
				packet.clear();
				result = false;
				break;
			
			default:
				;
		}
	}

	return result;
}

template<typename Stream>
void connection2<Stream>::newkeys(key_exchange& kex, boost::system::error_code &ec)
{
	m_crypto_engine.newkeys(kex, m_auth_state == detail::auth_state_type::authenticated);
}

template<typename Stream>
void connection2<Stream>::userauth_success(const std::string& host_version, const std::vector<uint8_t>& session_id)
{
	m_auth_state = detail::auth_state_type::authenticated;

	m_crypto_engine.enable_compression();

	m_host_version = host_version;
	m_session_id = session_id;
}

template<typename Stream>
void connection2<Stream>::process_channel_open(ipacket &in, opacket &out)
{
	channel_ptr c;

	std::string type;

	in >> type;

	try
	{
		// if (type == "x11")
		// 	c.reset(new x11_channel(shared_from_this()));
		// else if (type == "auth-agent@openssh.com" and m_forward_agent)
		// 	c.reset(new ssh_agent_channel(this->shared_from_this()));
	}
	catch (...)
	{
	}

	if (c)
	{
		in.message(msg_channel_open_confirmation);
		c->process(in);
		m_channels.push_back(c);
	}
	else
	{
		uint32_t host_channel_id;
		in >> host_channel_id;

		const uint32_t SSH_OPEN_UNKNOWN_CHANNEL_TYPE = 3;
		out = msg_channel_open_failure;
		out << host_channel_id << SSH_OPEN_UNKNOWN_CHANNEL_TYPE << "unsupported channel type"
			<< "en";
	}
}

template<typename Stream>
void connection2<Stream>::process_channel(ipacket &in, opacket &out, boost::system::error_code &ec)
{
	try
	{
		uint32_t channel_id;
		in >> channel_id;

		for (channel_ptr c : m_channels)
		{
			if (c->my_channel_id() == channel_id)
			{
				c->process(in);
				break;
			}
		}
	}
	catch (...)
	{
	}
}


}



int main() {
	using boost::asio::ip::tcp;

	boost::asio::io_context io_context;

	auto conn = std::make_shared<assh::connection2<boost::asio::ip::tcp::socket>>(io_context, "maartenx");

	tcp::resolver resolver(io_context);
	tcp::resolver::results_type endpoints = resolver.resolve("localhost", "2022");

	boost::asio::connect(conn->lowest_layer(), endpoints);
	conn->async_handshake([](const boost::system::error_code& ec)
	{
		std::cout << "handler, ec = " << ec.message() << std::endl;
		// t->close();
	});

	// auto c = std::make_shared<assh::connection>(io_context, "maarten", "localhost", 22);



	// assh::connection_pool pool(io_context);

	// auto c = pool.get("maarten", "localhost", 2022);

	// auto t = std::make_shared<assh::terminal_channel>(c);

	// auto handler = [](const std::string& a, const std::string& b)
	// {
	// 	std::cout << a << b << std::endl;
	// };

	// t->set_message_callbacks(handler, handler, handler);

	// t->open_with_pty(80, 24, "vt220", false, false, "/bin/ls",
	// 	[t](const boost::system::error_code& ec)
	// 	{
	// 		std::cout << "handler, ec = " << ec.message() << std::endl;
	// 		t->close();
	// 	});

	io_context.run();

	return 0;
}