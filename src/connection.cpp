//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <pinch/pinch.hpp>

#include <iostream>

#include <pinch/connection.hpp>
#include <pinch/channel.hpp>
#include <pinch/ssh_agent.hpp>
#include <pinch/x11_channel.hpp>
#include <pinch/error.hpp>
#include <pinch/port_forwarding.hpp>
#include <pinch/crypto-engine.hpp>
#include "pinch/ssh_agent_channel.hpp"

namespace pinch
{

// --------------------------------------------------------------------

const auto kKeepAliveInterval = std::chrono::seconds(60); // 60 seconds, should be ok?

// --------------------------------------------------------------------

const std::string
	kSSHVersionString("SSH-2.0-libpinch");

// --------------------------------------------------------------------

// --------------------------------------------------------------------

namespace detail
{

void async_connect_impl::async_connect_impl::process_userauth_failure(ipacket &in, opacket &out, boost::system::error_code &ec)
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
	else if (choose_protocol(s, "keyboard-interactive") == "keyboard-interactive" and credentials_request and ++m_password_attempts <= 3)
	{
		out = opacket(msg_userauth_request)
				<< user << "ssh-connection"
				<< "keyboard-interactive"
				<< "en"
				<< "";
		auth_state = auth_state_type::keyboard_interactive;
	}
	else if (choose_protocol(s, "password") == "password" and credentials_request and ++m_password_attempts <= 3)
	{
		auth_state = auth_state_type::password;
		credentials_request(auth_state_type::password, "", "password", "en", { { "password" , false } });
	}
	else
	{
		auth_state = auth_state_type::error;
		ec = error::make_error_code(error::no_more_auth_methods_available);
	}
}

void async_connect_impl::process_userauth_info_request(ipacket &in, opacket &out, boost::system::error_code &ec)
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

				credentials_request(auth_state_type::keyboard_interactive, name, instruction, language, prompts);
			}
			break;
		}
		default:
			ec = make_error_code(error::protocol_error);
	}
}

} // namespace detail

// --------------------------------------------------------------------

void basic_connection::userauth_success(const std::string& host_version, const blob& session_id, const blob& pk_hash)
{
	m_auth_state = authenticated;

	m_crypto_engine.enable_compression();

	m_host_version = host_version;
	m_session_id = session_id;
	m_private_key_hash = pk_hash;

	// start the read loop
	async_read();

	// tell all opening channels to open
	for (auto ch: m_channels)
		ch->open();
}

void basic_connection::handle_error(const boost::system::error_code &ec)
{
	if (ec)
	{
		for (auto ch: m_channels)
			ch->error(ec.message(), "");

		disconnect();
	}
}

void basic_connection::reset()
{
	m_auth_state = none;
	m_private_key_hash.clear();
	m_session_id.clear();
	m_crypto_engine.reset();
}

void basic_connection::disconnect()
{
	reset();

	// copy the list since calling Close will change it
	std::list<channel_ptr> channels(m_channels);
	for (auto ch: channels)
		ch->close();
}

void basic_connection::rekey()
{
	m_kex.reset(new key_exchange(m_host_version, m_session_id,
		[cb = m_validate_host_key_cb, host = m_host](const std::string& alg, const blob& hash)
		{
			return cb ? cb(host, alg, hash) : true;
		}));
	async_write(m_kex->init());
}

void basic_connection::send_credentials(auth_state_type state, const std::vector<std::string>& replies)
{
	switch (state)
	{
		case auth_state_type::keyboard_interactive:
		{
			opacket out(msg_userauth_info_response);
			out << replies.size();
			for (auto& r : replies)
				out << r;
			async_write(std::move(out));
			break;
		}

		case auth_state_type::password:
		{
			if (replies.size() == 1)
			{
				opacket out(msg_userauth_request);
				out << m_user << "ssh-connection" << "password" << false << replies[0];
				async_write(std::move(out));
			}
			else
				handle_error(error::make_error_code(error::auth_cancelled_by_user));
			break;
		}

		default:
			handle_error(error::make_error_code(error::auth_cancelled_by_user));
			break;
	}
}

// the read loop, this routine keeps calling itself until an error condition is met

void basic_connection::received_data(boost::system::error_code ec)
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

		async_read();
	}
	catch (...)
	{
		disconnect();
	}
}

void basic_connection::process_packet(ipacket& in)
{
	// update time for keep alive
	m_last_io = std::chrono::steady_clock::now();

	opacket out;
	boost::system::error_code ec;

	if (not (m_kex and m_kex->process(in, out, ec)))
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
				process_channel(in, out, ec);
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
				out << m_crypto_engine.get_next_out_seq_nr();
				async_write(std::move(out));
				break;
			}
		}

	if (ec)
		handle_error(ec);

	if (not out.empty())
		async_write(std::move(out));
}

bool basic_connection::receive_packet(ipacket& packet, boost::system::error_code& ec)
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
				disconnect();
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

void basic_connection::process_channel_open(ipacket &in, opacket &out)
{
	channel_ptr c;

	std::string type;

	in >> type;

	try
	{
		if (type == "x11")
			c.reset(new x11_channel(shared_from_this()));
		else if (type == "auth-agent@openssh.com" and m_forward_agent)
			c.reset(new ssh_agent_channel(this->shared_from_this()));
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

void basic_connection::process_channel(ipacket &in, opacket &out, boost::system::error_code &ec)
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

void basic_connection::open_channel(channel_ptr ch, uint32_t channel_id)
{
	if (std::find(m_channels.begin(), m_channels.end(), ch) == m_channels.end())
	{
		// some sanity check first
		assert(std::find_if(m_channels.begin(), m_channels.end(),
						[channel_id](channel_ptr ch) -> bool { return ch->my_channel_id() == channel_id; }) == m_channels.end());
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

void basic_connection::handle_banner(const std::string& message, const std::string& lang)
{
	for (auto c: m_channels)
		c->banner(message, lang);
}

void basic_connection::keep_alive()
{
	auto now = std::chrono::steady_clock::now();

	if (m_auth_state == authenticated and (now - m_last_io) > kKeepAliveInterval)
	{
		opacket out(msg_ignore);
		out << "Hello, world!";

		async_write(std::move(out), [self = shared_from_this(), now](const boost::system::error_code &ec, size_t) {
			if (not ec)
				self->m_last_io = now;
		});
	}
}

void basic_connection::forward_port(const std::string &local_address, uint16_t local_port,
									const std::string &remote_address, uint16_t remote_port)
{
	if (not m_port_forwarder)
		m_port_forwarder.reset(new port_forward_listener(shared_from_this()));
	m_port_forwarder->forward_port(local_address, local_port, remote_address, remote_port);
}

void basic_connection::forward_socks5(const std::string &local_address, uint16_t local_port)
{
	if (not m_port_forwarder)
		m_port_forwarder.reset(new port_forward_listener(shared_from_this()));
	m_port_forwarder->forward_socks5(local_address, local_port);
}

// --------------------------------------------------------------------

void connection::open()
{
	if (not is_open())
	{
		using namespace boost::asio::ip;

		// synchronous for now...

		tcp::resolver resolver(get_executor());
		tcp::resolver::results_type endpoints = resolver.resolve(m_host, std::to_string(m_port));

		boost::asio::connect(m_next_layer, endpoints);

// 		enum { start, resolving, connecting };

// 		auto resolver = std::make_shared<tcp::resolver>(get_executor());
// 		tcp::resolver::endpoint_type endpoint{};

// 		auto handler = [](const boost::system::error_code& ec) {};
// 		using Handler = decltype(handler);

// 		boost::asio::async_compose<Handler,void(boost::system::error_code)>(
// 			[
// 				&socket = m_next_layer,
// 				query = tcp::resolver::query(m_host, std::to_string(m_port)),
// 				resolver,
// 				endpoint,
// 				state = start
// 			]
// 			(auto& self, const boost::system::error_code& ec = {}, tcp::resolver::iterator endpoint_iterator = {}) mutable
// 			{
// 				if (ec and state == connecting and endpoint_iterator != boost::asio::ip::tcp::resolver::iterator())
// 				{
// 					auto endpoint = *endpoint_iterator++;							
// 					socket.async_connect(endpoint, std::move(self));
// 					return;
// 				}

// 				if (not ec)
// 				{
// 					switch (state)
// 					{
// 						case start:
// 							state = resolving;
// 							resolver->async_resolve(query, std::move(self));
// 							return;
						
// 						case resolving:
// 						{
// 							state = connecting;
// 							auto endpoint = *endpoint_iterator++;							
// 							socket.async_connect(endpoint, std::move(self));
// 							return;
// 						}

// 						case connecting:
// 							break;
// 					}
// 				}

// 				self.complete(ec);
// 			}, handler
// 		);
	}
}

// --------------------------------------------------------------------

class proxy_channel : public channel
{
public:
	proxy_channel(std::shared_ptr<basic_connection> connection, const std::string &nc_cmd, const std::string &user, const std::string &host, uint16_t port)
		: channel(connection), m_cmd(nc_cmd)
	{
		for (const auto& [pat, repl]: std::initializer_list<std::pair<std::string,std::string>>
			{ { "%r", user }, { "%h", host }, { "%p", std::to_string(port)}})
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
	: basic_connection(user, host, port), m_proxy(proxy), m_channel(new proxy_channel(m_proxy, nc_cmd, user, host, port))
{
}

proxied_connection::proxied_connection(std::shared_ptr<basic_connection> proxy, const std::string &user, const std::string &host, uint16_t port)
	: basic_connection(user, host, port), m_proxy(proxy), m_channel(new forwarding_channel(m_proxy, host, port))
{
}

proxied_connection::~proxied_connection()
{
	if (m_channel and m_channel->is_open())
		m_channel->close();
}

proxied_connection::executor_type proxied_connection::get_executor() noexcept
{
	return m_channel->lowest_layer().get_executor();
}

const proxied_connection::lowest_layer_type& proxied_connection::lowest_layer() const
{
	return m_channel->lowest_layer();
}

proxied_connection::lowest_layer_type& proxied_connection::lowest_layer()
{
	return m_channel->lowest_layer();
}

void proxied_connection::disconnect()
{
	basic_connection::disconnect();

	m_channel->close();
}

void proxied_connection::set_validate_callback(const validate_callback_type &cb)
{
	m_proxy->set_validate_callback(cb);
	basic_connection::set_validate_callback(cb);
}

bool proxied_connection::validate_host_key(const std::string &pk_alg, const blob &host_key)
{
	return m_validate_host_key_cb and m_validate_host_key_cb(m_host, pk_alg, host_key);
}

void proxied_connection::open()
{
	m_proxy->async_connect([](const boost::system::error_code&){}, m_channel);
}

bool proxied_connection::is_open() const
{
	return m_channel->is_open();
}

void proxied_connection::do_wait(std::unique_ptr<detail::wait_connection_op> op)
{
	assert(m_channel);

	switch (op->m_type)
	{
		case wait_type::read:
			m_channel->async_wait(channel::wait_type::read,
				[ wait_op = std::move(op) ]
				(const boost::system::error_code ec)
				{
					wait_op->complete(ec);
				});
			break;

		case wait_type::write:
			m_channel->async_wait(channel::wait_type::write,
				[ wait_op = std::move(op) ]
				(const boost::system::error_code ec)
				{
					wait_op->complete(ec);
				});
			break;

	}
}

} // namespace pinch
