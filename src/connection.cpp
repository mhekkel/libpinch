//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)


#include "pinch/ssh_agent_channel.hpp"
#include "pinch/channel.hpp"
#include "pinch/connection.hpp"
#include "pinch/crypto-engine.hpp"
#include "pinch/error.hpp"
#include "pinch/port_forwarding.hpp"
#include "pinch/ssh_agent.hpp"
#include "pinch/x11_channel.hpp"

#include <iostream>

namespace pinch
{

// --------------------------------------------------------------------

const std::string
	kSSHVersionString("SSH-2.0-libpinch");

// --------------------------------------------------------------------

host_key_reply always_trust_host_key_once(const std::string &host, const std::string &algorithm, const blob &key, host_key_state state)
{
	return host_key_reply::trust_once;
}

// --------------------------------------------------------------------

void basic_connection::userauth_success(const std::string &host_version, const blob &session_id, const blob &pk_hash)
{
	m_auth_state = authenticated;

	m_crypto_engine.enable_compression();

	m_host_version = host_version;
	m_session_id = session_id;
	m_private_key_hash = pk_hash;

	// start the read loop
	read_loop();

	// tell all the waiting ops
	auto wait_ops = m_waiting_ops;

	for (auto &op : wait_ops)
	{
		if (op->m_type != wait_type::open)
			continue;

		m_waiting_ops.erase(std::find(m_waiting_ops.begin(), m_waiting_ops.end(), op));

		op->complete();
		delete op;
	}

	// start keep alive timer, if needed
	m_last_io = std::chrono::steady_clock::now();
	if (m_keep_alive_interval > std::chrono::seconds(0))
		keep_alive_time_out();
}

void basic_connection::handle_error(const asio_system_ns::error_code &ec)
{
	if (ec)
	{
		for (auto ch : m_channels)
			ch->error(ec.message(), "");

		close();
	}
}

void basic_connection::close()
{
	m_auth_state = none;
	m_private_key_hash.clear();
	m_session_id.clear();
	m_crypto_engine.reset();

	m_keep_alive_timer.expires_at(asio_ns::steady_timer::time_point::max());

	if (m_port_forwarder)
		m_port_forwarder->connection_closed();

	// copy the list since calling Close will change it
	std::list<channel_ptr> channels(m_channels);
	for (auto ch : channels)
		ch->close();
}

void basic_connection::rekey()
{
	m_kex.reset(new key_exchange(m_host_version, m_session_id));
	async_write(m_kex->init());
}

// the read loop, this routine keeps calling itself until an error condition is met

void basic_connection::read_loop(asio_system_ns::error_code ec, std::size_t bytes_transferred)
{
	if (ec)
	{
		handle_error(ec);
		return;
	}

	// don't process data at all if we're no longer willing
	if (m_auth_state != authenticated)
		return;

	try
	{
		for (;;)
		{
			auto p = m_crypto_engine.get_next_packet(m_response, ec);

			if (ec)
			{
				handle_error(ec);
				break;
			}

			if (not p)
				break;

			process_packet(*p);
		}

		using namespace std::placeholders;
		async_read_some(asio_ns::basic_streambuf_ref(m_response), std::bind(&basic_connection::read_loop, this, _1, _2));
	}
	catch (...)
	{
		close();
	}
}

void basic_connection::process_packet(ipacket &in)
{
	// update time for keep alive
	m_last_io = std::chrono::steady_clock::now();
	m_keep_alive_timeouts = 0;

	opacket out;
	asio_system_ns::error_code ec;

	if (not(m_kex and m_kex->process(in, out, ec)))
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
				close();
				break;

			case msg_kexinit:
				rekey();
				m_kex->process(in, out, ec);
				break;

			case msg_newkeys:
				m_crypto_engine.newkeys(*m_kex, true);
				m_kex.reset();
				break;

			// channel
			case msg_channel_open:
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
				process_channel(in);
				break;

			case msg_global_request:
			{
				std::string request;
				bool want_reply;
				in >> request >> want_reply;
				if (want_reply)
					async_write(opacket(msg_request_failure));
				break;
			}

			default:
			{
				opacket out(msg_unimplemented);
				out << in.nr();
				async_write(std::move(out));
				break;
			}
		}

	if (ec)
		handle_error(ec);

	if (not out.empty())
		async_write(std::move(out));
}

std::unique_ptr<ipacket> basic_connection::receive_packet()
{
	asio_system_ns::error_code ec;

	auto result = m_crypto_engine.get_next_packet(m_response, ec);

	if (ec)
		throw asio_system_ns::system_error(ec);

	if (result)
	{
		switch ((message_type)*result)
		{
			case msg_disconnect:
				close();
				break;

			case msg_service_request:
				close();
				break;

			case msg_ignore:
			case msg_unimplemented:
			case msg_debug:
				result.reset(nullptr);
				break;

			default:;
		}
	}

	return result;
}

void basic_connection::process_channel_open(ipacket &in, opacket &out)
{
	channel_ptr c;

	std::string type;

	in >> type;

	if (type == "x11")
		c.reset(new x11_channel(shared_from_this()));
	else if (type == "auth-agent@openssh.com" and m_forward_agent)
		c.reset(new ssh_agent_channel(shared_from_this()));

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

void basic_connection::process_channel(ipacket &in)
{
	try
	{
		uint32_t channel_id{};
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

void basic_connection::open_channel(channel_ptr ch, uint32_t channel_id)
{
	if (std::find(m_channels.begin(), m_channels.end(), ch) == m_channels.end())
	{
		// some sanity check first
		assert(std::find_if(m_channels.begin(), m_channels.end(),
				   [channel_id](channel_ptr ch) -> bool
				   { return ch->my_channel_id() == channel_id; }) == m_channels.end());
		assert(not ch->is_open());

		m_channels.push_back(ch);
	}

	if (m_auth_state == authenticated)
	{
		opacket out(msg_channel_open);
		ch->fill_open_opacket(out);
		async_write(std::move(out));
	}
}

void basic_connection::close_channel(channel_ptr ch, uint32_t channel_id)
{
	if (ch->is_open())
	{
		if (m_auth_state == authenticated)
		{
			opacket out(msg_channel_close);
			out << channel_id;
			async_write(std::move(out));
		}

		ch->closed();
	}

	m_channels.erase(
		std::remove(m_channels.begin(), m_channels.end(), ch),
		m_channels.end());
}

bool basic_connection::has_open_channels()
{
	bool channel_open = false;

	for (auto c : m_channels)
	{
		if (c->is_open())
		{
			channel_open = true;
			break;
		}
	}

	return channel_open;
}

void basic_connection::handle_banner(const std::string &message, const std::string &lang)
{
	for (auto c : m_channels)
		c->banner(message, lang);
}

void basic_connection::keep_alive(std::chrono::seconds interval, uint32_t max_timeouts)
{
	m_keep_alive_interval = interval;
	m_max_keep_alive_timeouts = max_timeouts;

	m_keep_alive_timer.cancel();

	if (m_keep_alive_interval > std::chrono::seconds(0))
	{
		m_keep_alive_timer.expires_after(m_keep_alive_interval);
		m_keep_alive_timer.async_wait(std::bind(&basic_connection::keep_alive_time_out, this, std::placeholders::_1));
	}
}

void basic_connection::keep_alive_time_out(const asio_system_ns::error_code &ec)
{
	if (ec == asio_ns::error::operation_aborted)
		return;

	time_point_type now = std::chrono::steady_clock::now();
	std::chrono::seconds idle = std::chrono::duration_cast<std::chrono::seconds>(now - m_last_io);

	// See if we really need to send a packet.
	if (not ec and idle >= m_keep_alive_interval and is_open())
	{
		if (++m_keep_alive_timeouts > m_max_keep_alive_timeouts)
			handle_error(error::make_error_code(error::keep_alive_timeout));
		else
		{
			opacket out(msg_global_request);
			out << "keepalive@salt.hekkelman.com" << true;
			async_write(std::move(out), [this](asio_system_ns::error_code ec, std::size_t bytes_transferred)
				{
				if (ec)
					handle_error(ec); });

			idle = std::chrono::seconds(0);
		}
	}

	if (m_keep_alive_interval > std::chrono::seconds(1) and is_open())
	{
		m_keep_alive_timer.expires_after(m_keep_alive_interval);
		m_keep_alive_timer.async_wait(std::bind(&basic_connection::keep_alive_time_out, this, std::placeholders::_1));
	}
}

void basic_connection::forward_port(uint16_t local_port, const std::string &remote_address, uint16_t remote_port)
{
	if (not m_port_forwarder)
		m_port_forwarder.reset(new port_forward_listener(shared_from_this()));
	m_port_forwarder->forward_port(local_port, remote_address, remote_port);
}

void basic_connection::forward_socks5(uint16_t local_port)
{
	if (not m_port_forwarder)
		m_port_forwarder.reset(new port_forward_listener(shared_from_this()));
	m_port_forwarder->forward_socks5(local_port);
}

void basic_connection::forward_remote(const std::string &remote_socket, const std::string &local_socket)
{
	
}

// --------------------------------------------------------------------
// Handshake code

void basic_connection::do_open(std::unique_ptr<detail::open_connection_op> op)
{
	asio_system_ns::error_code ec;

	if (m_auth_state == authenticated)
		op->complete(ec);
	else if (m_auth_state == handshake)
		async_wait(detail::connection_wait_type::open, [op = std::move(op)](asio_system_ns::error_code ec)
			{ op->complete(ec); });
	else
	{
		m_auth_state = handshake;
		asio_ns::co_spawn(get_executor(), do_handshake(std::move(op)), asio_ns::detached);
	}
}

asio_ns::awaitable<void> basic_connection::do_handshake(std::unique_ptr<detail::open_connection_op> op)
{
	try
	{
		co_await async_open_next_layer(asio_ns::use_awaitable);
		co_await async_wait(wait_type::write, asio_ns::use_awaitable);

		asio_ns::streambuf buffer;
		std::ostream os(&buffer);
		os << kSSHVersionString << "\r\n";
		co_await asio_ns::async_write(*this, buffer, asio_ns::use_awaitable);

		co_await asio_ns::async_read_until(*this, m_response, "\n", asio_ns::use_awaitable);

		std::string host_version;
		{
			std::istream is(&m_response);
			std::getline(is, host_version);
		}

		while (std::isspace(host_version.back()))
			host_version.pop_back();

		if (not host_version.starts_with("SSH-2.0"))
			throw asio_system_ns::system_error(error::make_error_code(error::protocol_version_not_supported));

		auto kex = std::make_unique<key_exchange>(host_version);
		co_await async_write(kex->init(), asio_ns::use_awaitable);

		co_await async_read_some(asio_ns::basic_streambuf_ref(m_response), asio_ns::use_awaitable);

		for (;;)
		{
			auto in = receive_packet();

			if (not in)
			{
				co_await async_read_some(asio_ns::basic_streambuf_ref(m_response), asio_ns::use_awaitable);
				continue;
			}

			if (*in == msg_newkeys)
			{
				if (co_await async_accept_host_key(kex->get_host_key_pk_type(), kex->get_host_key(), asio_ns::use_awaitable))
					break;

				throw asio_system_ns::system_error(error::make_error_code(error::host_key_not_verifiable));
				break;
			}

			opacket out = kex->process(*in);
			if (out)
				co_await async_write(std::move(out), asio_ns::use_awaitable);
		}

		newkeys(*kex);

		co_await async_write(opacket(msg_service_request, "ssh-userauth"), asio_ns::use_awaitable);

		// we might not be known yet
		ssh_agent::instance().register_connection(shared_from_this());

		std::deque<ssh_private_key> private_keys;

		// fetch the private keys
		for (auto &pk : ssh_agent::instance())
			private_keys.push_back(pk);

		blob private_key_hash;
		auth_state_type auth_state = auth_state_type::none;
		int password_attempts = 0;

		while (m_auth_state != authenticated)
		{
			auto in = receive_packet();

			if (not in)
			{
				co_await async_read_some(asio_ns::basic_streambuf_ref(m_response), asio_ns::use_awaitable);
				continue;
			}

			switch ((message_type)*in)
			{
				case msg_service_accept:
					co_await async_write(opacket(msg_userauth_request, m_user, "ssh-connection", "none"), asio_ns::use_awaitable);
					continue;

				case msg_userauth_failure:
				{
					std::string s;
					bool partial;

					*in >> s >> partial;

					private_key_hash.clear();

					if (choose_protocol(s, "publickey") == "publickey" and not private_keys.empty())
					{
						auto &pk = private_keys.front();

						opacket out(msg_userauth_request,
							m_user, "ssh-connection",
							"publickey", false,
							pk.get_type(), pk.get_blob());

						private_keys.pop_front();
						auth_state = auth_state_type::public_key;

						co_await async_write(std::move(out), asio_ns::use_awaitable);
						continue;
					}

					if (choose_protocol(s, "keyboard-interactive") == "keyboard-interactive" and ++password_attempts <= 3)
					{
						auth_state = auth_state_type::keyboard_interactive;
						co_await async_write(opacket(msg_userauth_request, m_user, "ssh-connection", "keyboard-interactive", "en", ""), asio_ns::use_awaitable);
						continue;
					}

					if (choose_protocol(s, "password") == "password" and ++password_attempts <= 3)
					{
						std::string password = co_await async_provide_password(asio_ns::use_awaitable);
						if (password.empty())
							throw asio_system_ns::system_error(error::make_error_code(error::auth_cancelled_by_user));

						auth_state = auth_state_type::password;
						co_await async_write(opacket(msg_userauth_request, m_user, "ssh-connection", "password", false, password), asio_ns::use_awaitable);
						continue;
					}

					auth_state = auth_state_type::error;
					throw asio_system_ns::system_error(error::make_error_code(error::no_more_auth_methods_available));
				}

				case msg_userauth_banner:
				{
					std::string msg, lang;
					*in >> msg >> lang;
					handle_banner(msg, lang);
					break;
				}

				case msg_userauth_info_request:
					if (auth_state == auth_state_type::public_key)
					{
						std::string alg;
						ipacket blob;

						*in >> alg >> blob;

						opacket session_id;
						session_id << kex->session_id();

						ssh_private_key pk(ssh_agent::instance().get_key(blob));

						opacket out(msg_userauth_request);

						out << m_user << "ssh-connection"
							<< "publickey" << true << pk.get_type() << blob
							<< pk.sign(session_id, out);

						// store the hash for this private key
						private_key_hash = pk.get_hash();

						co_await async_write(std::move(out), asio_ns::use_awaitable);
						continue;
					}

					if (auth_state == auth_state_type::keyboard_interactive)
					{
						std::string name, instruction, language;
						int32_t numPrompts = 0;

						*in >> name >> instruction >> language >> numPrompts;

						if (numPrompts == 0)
							co_await async_write(opacket(msg_userauth_info_response, numPrompts), asio_ns::use_awaitable);
						else
						{
							std::vector<prompt> prompts(numPrompts);

							for (auto &p : prompts)
								*in >> p.str >> p.echo;

							auto replies = co_await async_provide_credentials(name, instruction, language, prompts, asio_ns::use_awaitable);

							if (replies.empty())
								throw asio_system_ns::system_error(error::make_error_code(error::auth_cancelled_by_user));

							opacket out(msg_userauth_info_response, replies.size());

							for (auto &r : replies)
								out << r;
							
							co_await async_write(std::move(out), asio_ns::use_awaitable);
						}
						continue;
					}

					throw asio_system_ns::system_error(make_error_code(error::protocol_error));
					break;

				case msg_userauth_success:
					userauth_success(host_version, kex->session_id(), private_key_hash);
					break;

				default:
#ifndef NDEBUG
					std::cerr << "Unexpected packet: " << in << std::endl;
#endif
					break;
			}
		}

		op->complete({});
	}
	catch (const asio_system_ns::system_error &e)
	{
		op->complete(e.code());
		close();
	}
	catch (...)
	{
		op->complete(make_error_code(error::channel_closed));
		close();
	}
}

// --------------------------------------------------------------------

void connection::open_next_layer(std::unique_ptr<detail::wait_connection_op> op)
{
	if (m_next_layer.is_open())
		op->complete({});
	else
	{
		using namespace asio_ns::ip;

		// synchronous for now...
		asio_system_ns::error_code ec;

		tcp::resolver resolver(get_executor());
		tcp::resolver::results_type endpoints = resolver.resolve(m_host, std::to_string(m_port), ec);

		if (ec)
			op->complete(ec);
		else
		{
			asio_ns::async_connect(m_next_layer, endpoints,
				[self = shared_from_this(), op = std::move(op)](const asio_system_ns::error_code &ec, tcp::resolver::endpoint_type)
				{
					op->complete(ec);
				});
		}
	}
}

// --------------------------------------------------------------------

class proxy_channel : public channel
{
  public:
	proxy_channel(std::shared_ptr<basic_connection> connection, const std::string &nc_cmd, const std::string &user, const std::string &host, uint16_t port)
		: channel(connection)
		, m_cmd(nc_cmd)
	{
		for (const auto &[pat, repl] : std::initializer_list<std::pair<std::string, std::string>>{{"%r", user}, {"%h", host}, {"%p", std::to_string(port)}})
		{
			for (auto p = m_cmd.find(pat); p != std::string::npos; p = m_cmd.find(pat, p + repl.length()))
				m_cmd.replace(p, 2, repl);
		}
	}

	virtual void opened()
	{
		channel::opened();
		send_request_and_command("exec", m_cmd);
	}

	std::string m_cmd;
};

// --------------------------------------------------------------------

proxied_connection::proxied_connection(std::shared_ptr<basic_connection> proxy, const std::string &nc_cmd, const std::string &user, const std::string &host, uint16_t port)
	: basic_connection(proxy->get_executor().context(), user, host, port)
	, m_proxy(proxy)
	, m_channel(new proxy_channel(m_proxy, nc_cmd, user, host, port))
{
}

proxied_connection::proxied_connection(std::shared_ptr<basic_connection> proxy, const std::string &user, const std::string &host, uint16_t port)
	: basic_connection(proxy->get_executor().context(), user, host, port)
	, m_proxy(proxy)
	, m_channel(new forwarding_channel(m_proxy, 22, host, port))
{
}

proxied_connection::~proxied_connection()
{
	if (m_channel and m_channel->is_open())
		m_channel->close();
}

const proxied_connection::lowest_layer_type &proxied_connection::lowest_layer() const
{
	return m_channel->lowest_layer();
}

proxied_connection::lowest_layer_type &proxied_connection::lowest_layer()
{
	return m_channel->lowest_layer();
}

void proxied_connection::close()
{
	basic_connection::close();

	m_channel->close();
}

bool proxied_connection::next_layer_is_open() const
{
	return m_channel and m_channel->is_open();
}

void proxied_connection::open_next_layer(std::unique_ptr<detail::wait_connection_op> op)
{
	if (m_channel->is_open())
		op->complete({});
	else
	{
		using namespace std::placeholders;

		if (m_accept_host_key_handler)
		{
			if (m_callback_executor)
				m_proxy->set_callback_executor(m_callback_executor);

			m_proxy->set_accept_host_key_handler(
				[this]
				(const std::string &host, const std::string &algorithm, const blob &key, host_key_state state)
				{
					return this->m_accept_host_key_handler(host, algorithm, key, state);
				});
		}

		m_channel->async_open(
			[op = std::move(op)](const asio_system_ns::error_code &ec)
			{
				op->complete(ec);
			});
	}
}

void proxied_connection::keep_alive(std::chrono::seconds interval, uint32_t max_timeouts)
{
	m_proxy->keep_alive(interval, max_timeouts);

	m_keep_alive_interval = interval;
	m_max_keep_alive_timeouts = max_timeouts;

	m_keep_alive_timer.cancel();

	if (m_keep_alive_interval > std::chrono::seconds(0))
	{
		m_keep_alive_timer.expires_after(m_keep_alive_interval);
		m_keep_alive_timer.async_wait(std::bind(&proxied_connection::keep_alive_time_out, this, std::placeholders::_1));
	}
}

void proxied_connection::do_wait(std::unique_ptr<detail::wait_connection_op> op)
{
	assert(m_channel);

	switch (op->m_type)
	{
		// dubious...
		case wait_type::open:
			m_channel->async_wait(channel::wait_type::open,
				[wait_op = std::move(op)](const asio_system_ns::error_code ec)
				{
					wait_op->complete(ec);
				});
			break;

		case wait_type::read:
			m_channel->async_wait(channel::wait_type::read,
				[wait_op = std::move(op)](const asio_system_ns::error_code ec)
				{
					wait_op->complete(ec);
				});
			break;

		case wait_type::write:
			m_channel->async_wait(channel::wait_type::write,
				[wait_op = std::move(op)](const asio_system_ns::error_code ec)
				{
					wait_op->complete(ec);
				});
			break;
	}
}

} // namespace pinch
