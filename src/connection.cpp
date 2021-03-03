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
#include <pinch/key_exchange.hpp>
#include <pinch/error.hpp>
#include <pinch/port_forwarding.hpp>
#include <pinch/crypto-engine.hpp>
#include "pinch/ssh_agent_channel.hpp"

namespace io = boost::iostreams;
namespace ba = boost::algorithm;

namespace pinch
{

// --------------------------------------------------------------------

const int64_t kKeepAliveInterval = 60; // 60 seconds, should be ok?

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
	else if (choose_protocol(s, "keyboard-interactive") == "keyboard-interactive" and m_keyboard_interactive_cb and ++m_password_attempts <= 3)
	{
		out = opacket(msg_userauth_request)
				<< user << "ssh-connection"
				<< "keyboard-interactive"
				<< "en"
				<< "";
		auth_state = auth_state_type::keyboard_interactive;
	}
	else if (choose_protocol(s, "password") == "password" and request_password and ++m_password_attempts <= 3)
	{
		auth_state = auth_state_type::password;
		request_password();
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

				m_keyboard_interactive_cb(name, language, prompts);
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
	m_last_io = 0;
}

void basic_connection::disconnect()
{
	reset();

	// copy the list since calling Close will change it
	std::list<channel_ptr> channels(m_channels);
	for (auto ch: channels)
		ch->close();
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
	struct timeval tv;
	gettimeofday(&tv, nullptr);

	if (m_auth_state == authenticated and m_last_io + kKeepAliveInterval < static_cast<int64_t>(tv.tv_sec))
	{
		opacket out(msg_ignore);
		out << "Hello, world!";

		async_write(std::move(out), [self = shared_from_this(), tv](const boost::system::error_code &ec, size_t) {
			if (not ec)
				self->m_last_io = tv.tv_sec;
		});
	}
}

// --------------------------------------------------------------------


// basic_connection::basic_connection(boost::asio::io_service &io_service, const string &user)
// 	: m_io_service(io_service)
// 	, m_user(user)
// 	, m_authenticated(false)
// 	, m_auth_state(auth_state_none)
// 	, m_forward_agent(false)
// 	, m_port_forwarder(nullptr)
// 	, m_alg_kex(kKeyExchangeAlgorithms)
// 	, m_alg_enc_c2s(kEncryptionAlgorithms)
// 	, m_alg_ver_c2s(kMacAlgorithms)
// 	, m_alg_cmp_c2s(kCompressionAlgorithms)
// 	, m_alg_enc_s2c(kEncryptionAlgorithms)
// 	, m_alg_ver_s2c(kMacAlgorithms)
// 	, m_alg_cmp_s2c(kCompressionAlgorithms)
// {
// 	reset();
// }

// basic_connection::~basic_connection()
// {
// 	// ssh_agent::instance().unregister_connection(shared_from_this());

// 	// delete m_port_forwarder;
// }

// void basic_connection::set_algorithm(algorithm alg, direction dir, const string &preferred)
// {
// 	switch (alg)
// 	{
// 		case algorithm::keyexchange:
// 			m_alg_kex = preferred;
// 			break;

// 		case algorithm::encryption:
// 			if (dir != direction::c2s)
// 				m_alg_enc_s2c = preferred;
// 			if (dir != direction::s2c)
// 				m_alg_enc_c2s = preferred;
// 			break;

// 		case algorithm::verification:
// 			if (dir != direction::c2s)
// 				m_alg_ver_s2c = preferred;
// 			if (dir != direction::s2c)
// 				m_alg_ver_c2s = preferred;
// 			break;

// 		case algorithm::compression:
// 			if (dir != direction::c2s)
// 				m_alg_cmp_s2c = preferred;
// 			if (dir != direction::s2c)
// 				m_alg_cmp_c2s = preferred;
// 			break;
// 	}
// }

// void basic_connection::set_validate_callback(const validate_callback_type &cb)
// {
// 	m_validate_host_key_cb = cb;
// }

// void basic_connection::set_password_callback(const password_callback_type &cb)
// {
// 	m_request_password_cb = cb;
// }

// void basic_connection::set_keyboard_interactive_callback(const keyboard_interactive_callback_type &cb)
// {
// 	m_keyboard_interactive_cb = cb;
// }

// void basic_connection::reset()
// {
// 	m_authenticated = false;
// 	m_auth_state = auth_state_none;
// 	m_private_key_hash.clear();
// 	m_key_exchange.reset();
// 	m_session_id.clear();
// 	m_packet.clear();
// 	m_encryptor.reset(nullptr);
// 	m_decryptor.reset(nullptr);
// 	m_signer.reset(nullptr);
// 	m_verifier.reset(nullptr);
// 	m_compressor.reset(nullptr);
// 	m_decompressor.reset(nullptr);
// 	m_delay_decompressor = m_delay_compressor = false;
// 	m_password_attempts = 0;
// 	m_in_seq_nr = m_out_seq_nr = 0;
// 	m_iblocksize = m_oblocksize = 8;
// 	m_last_io = 0;
// }

// void basic_connection::disconnect()
// {
// 	reset();

// 	// copy the list since calling Close will change it
// 	list<channel_ptr> channels(m_channels);
// 	for_each(channels.begin(), channels.end(), [](channel_ptr c) { c->close(); });
// }

// void basic_connection::keep_alive()
// {
// 	struct timeval tv;
// 	gettimeofday(&tv, nullptr);

// 	if (m_authenticated and m_last_io + kKeepAliveInterval < static_cast<int64_t>(tv.tv_sec))
// 	{
// 		opacket out(msg_ignore);
// 		out << "Hello, world!";

// 		auto self(shared_from_this());
// 		async_write(move(out), [self, this, tv](const boost::system::error_code &ec, size_t bytes_transferred) {
// 			if (not ec)
// 				this->m_last_io = tv.tv_sec;
// 		});
// 	}
// }

// void basic_connection::handle_error(const boost::system::error_code &ec)
// {
// 	if (ec)
// 	{
// #if DEBUG
// 		cerr << ec << endl;
// #endif

// 		for_each(m_channels.begin(), m_channels.end(), [&ec](channel_ptr ch) { ch->error(ec.message(), ""); });

// 		disconnect();
// 		handle_connect_result(ec);
// 	}
// }

// void basic_connection::rekey()
// {
// 	m_key_exchange.reset(new key_exchange(m_host_version, m_session_id));
// 	async_write(m_key_exchange->init());
// }

// void basic_connection::forward_agent(bool forward)
// {
// 	m_forward_agent = forward;
// }

// void basic_connection::forward_port(const string &local_address, int16_t local_port,
// 									const string &remote_address, int16_t remote_port)
// {
// 	// if (m_port_forwarder == nullptr)
// 	// 	m_port_forwarder = new port_forward_listener(shared_from_this());
// 	// m_port_forwarder->forward_port(local_address, local_port, remote_address, remote_port);
// }

// void basic_connection::forward_socks5(const string &local_address, int16_t local_port)
// {
// 	// if (m_port_forwarder == nullptr)
// 	// 	m_port_forwarder = new port_forward_listener(shared_from_this());
// 	// m_port_forwarder->forward_socks5(local_address, local_port);
// }

// string basic_connection::get_connection_parameters(direction dir) const
// {
// 	string result;

// 	// ipacket payload(m_host_payload.data(), m_host_payload.size());

// 	string key_exchange_alg, server_host_key_alg, encryption_alg_c2s, encryption_alg_s2c,
// 		MAC_alg_c2s, MAC_alg_s2c, compression_alg_c2s, compression_alg_s2c;

// 	// payload.skip(16);
// 	// payload >> key_exchange_alg >> server_host_key_alg >> encryption_alg_c2s >> encryption_alg_s2c >> MAC_alg_c2s >> MAC_alg_s2c >> compression_alg_c2s >> compression_alg_s2c;

// 	if (dir == direction::c2s)
// 	{
// 		result = choose_protocol(encryption_alg_c2s, m_alg_enc_c2s) + '/' +
// 					choose_protocol(MAC_alg_c2s, m_alg_ver_c2s);

// 		string compression = choose_protocol(compression_alg_c2s, m_alg_cmp_c2s);
// 		if (compression != "none")
// 			result = result + '/' + compression;
// 	}
// 	else
// 	{
// 		result = choose_protocol(encryption_alg_s2c, m_alg_enc_s2c) + '/' +
// 					choose_protocol(MAC_alg_s2c, m_alg_ver_s2c);

// 		string compression = choose_protocol(compression_alg_s2c, m_alg_cmp_s2c);
// 		if (compression != "none")
// 			result = result + '/' + compression;
// 	}

// 	return result;
// }

// string basic_connection::get_key_exchange_algoritm() const
// {
// 	// ipacket payload(m_host_payload.data(), m_host_payload.size());

// 	// string key_exchange_alg;

// 	// payload.skip(16);
// 	// payload >> key_exchange_alg;

// 	// return choose_protocol(key_exchange_alg, m_alg_kex);

// 	return {};
// }

// void basic_connection::handle_connect_result(const boost::system::error_code &ec)
// {
// 	if (ec)
// 		m_auth_state = auth_state_none;
// 	else
// 		m_auth_state = auth_state_connected;

// 	auto self(shared_from_this());
// 	for_each(m_connect_handlers.begin(), m_connect_handlers.end(),
// 				[self, this, &ec](basic_connect_handler *h) {
// 					try
// 					{
// 						h->handle_connect(ec, m_io_service);
// 					}
// 					catch (...)
// 					{
// 					}
// 					delete h;
// 				});

// 	m_connect_handlers.clear();

// 	if (ec)
// 		disconnect();
// }

// void basic_connection::start_handshake()
// {
// 	if (m_auth_state == auth_state_none)
// 	{
// 		reset();

// 		m_auth_state = auth_state_connecting;

// 		boost::asio::streambuf *request(new boost::asio::streambuf);
// 		ostream out(request);
// 		out << kSSHVersionString << "\r\n";

// 		auto self(shared_from_this());
// 		async_write(request, [self, this](const boost::system::error_code &ec, size_t bytes_transferred) {
// 			handle_protocol_version_request(ec, bytes_transferred);
// 			//			delete request;
// 		});
// 	}
// }

// void basic_connection::handle_protocol_version_request(const boost::system::error_code &ec, size_t)
// {
// 	if (ec)
// 		handle_connect_result(ec);
// 	else
// 		async_read_version_string();
// }

// void basic_connection::handle_protocol_version_response(const boost::system::error_code &ec, size_t)
// {
// 	if (ec)
// 		handle_connect_result(ec);
// 	else
// 	{
// 		istream response_stream(&m_response);

// 		getline(response_stream, m_host_version);
// 		ba::trim_right(m_host_version);

// 		if (ba::starts_with(m_host_version, "SSH-2.0"))
// 		{
// 			rekey();

// 			// start read loop
// 			received_data(boost::system::error_code());
// 		}
// 		else
// 			handle_connect_result(error::make_error_code(error::protocol_version_not_supported));
// 	}
// }

// // the read loop, this routine keeps calling itself until an error condition is met
// void basic_connection::received_data(const boost::system::error_code &ec)
// {
// 	if (ec)
// 	{
// 		handle_error(ec);
// 		return;
// 	}

// 	// don't process data at all if we're no longer willing
// 	if (m_auth_state == auth_state_none)
// 		return;

// 	try
// 	{
// 		while (m_response.size() >= m_iblocksize)
// 		{
// 			if (not m_packet.complete())
// 			{
// 				vector<uint8_t> block(m_iblocksize);
// 				m_response.sgetn(reinterpret_cast<char *>(block.data()), m_iblocksize);

// 				if (m_decryptor)
// 				{
// 					vector<uint8_t> data(m_iblocksize);
// 					m_decryptor->ProcessData(data.data(), block.data(), m_iblocksize);
// 					swap(data, block);
// 				}

// 				if (m_verifier)
// 				{
// 					if (m_packet.empty())
// 					{
// 						for (int32_t i = 3; i >= 0; --i)
// 						{
// 							uint8_t b = m_in_seq_nr >> (i * 8);
// 							m_verifier->Update(&b, 1);
// 						}
// 					}

// 					m_verifier->Update(block.data(), block.size());
// 				}

// 				m_packet.append(block);
// 			}

// 			if (m_packet.complete())
// 			{
// 				if (m_verifier)
// 				{
// 					if (m_response.size() < m_verifier->DigestSize())
// 						break;

// 					vector<uint8_t> digest(m_verifier->DigestSize());
// 					m_response.sgetn(reinterpret_cast<char *>(digest.data()), m_verifier->DigestSize());

// 					if (not m_verifier->Verify(digest.data()))
// 					{
// 						handle_error(error::make_error_code(error::mac_error));
// 						return;
// 					}
// 				}

// 				if (m_decompressor)
// 				{
// 					boost::system::error_code ec;
// 					m_packet.decompress(*m_decompressor, ec);
// 					if (ec)
// 					{
// 						handle_error(ec);
// 						break;
// 					}
// 				}

// 				process_packet(m_packet);

// 				m_packet.clear();
// 				++m_in_seq_nr;
// 			}
// 		}

// 		uint32_t at_least = m_iblocksize;
// 		if (m_response.size() >= m_iblocksize)
// 		{
// 			// if we arrive here, we might have read a block, but not the digest?
// 			// call readsome with 0 as at-least, that will return something we hope.
// 			at_least = 1;
// 		}
// 		else
// 			at_least -= m_response.size();

// 		async_read(at_least);
// 	}
// 	catch (...)
// 	{
// 		try
// 		{
// 			disconnect();
// 		}
// 		catch (...)
// 		{
// 		}
// 		throw;
// 	}
// }

// void basic_connection::process_packet(ipacket &in)
// {
// 	// update time for keep alive
// 	struct timeval tv;
// 	gettimeofday(&tv, nullptr);
// 	m_last_io = tv.tv_sec;

// 	opacket out;
// 	boost::system::error_code ec;

// 	bool handled = false;

// 	if (m_key_exchange)
// 		handled = m_key_exchange->process(in, out, ec);

// 	if (not handled)
// 	{
// 		handled = true;

// 		switch ((message_type)in)
// 		{
// 			case msg_disconnect:
// 			{
// 				uint32_t reasonCode;
// 				in >> reasonCode;
// 				handle_error(error::make_error_code(error::disconnect_errors(reasonCode)));
// 				break;
// 			}

// 			case msg_ignore:
// 			case msg_unimplemented:
// 			case msg_debug:
// 				break;

// 			case msg_service_request:
// 				disconnect();
// 				break;

// 			case msg_service_accept:
// 				process_service_accept(in, out, ec);
// 				break;

// 			case msg_kexinit:
// 				process_kexinit(in, out, ec);
// 				break;

// 			case msg_newkeys:
// 				process_newkeys(in, out, ec);
// 				break;

// 			case msg_userauth_success:
// 				process_userauth_success(in, out, ec);
// 				break;
// 			case msg_userauth_failure:
// 				process_userauth_failure(in, out, ec);
// 				break;
// 			case msg_userauth_banner:
// 				process_userauth_banner(in, out, ec);
// 				break;
// 			case msg_userauth_info_request:
// 				process_userauth_info_request(in, out, ec);
// 				break;

// 			// channel
// 			case msg_channel_open:
// 				if (m_authenticated)
// 					process_channel_open(in, out);
// 				break;
// 			case msg_channel_open_confirmation:
// 			case msg_channel_open_failure:
// 			case msg_channel_window_adjust:
// 			case msg_channel_data:
// 			case msg_channel_extended_data:
// 			case msg_channel_eof:
// 			case msg_channel_close:
// 			case msg_channel_request:
// 			case msg_channel_success:
// 			case msg_channel_failure:
// 				if (m_authenticated)
// 					process_channel(in, out, ec);
// 				break;

// 			default:
// 			{
// 				opacket out(msg_unimplemented);
// 				out << (uint32_t)m_in_seq_nr;
// 				async_write(move(out));
// 				break;
// 			}
// 		}
// 	}

// 	if (ec)
// 		handle_connect_result(ec);

// 	if (not out.empty())
// 		async_write(move(out));
// }

// bool basic_connection::validate_host_key(const string &pk_alg, const vector<uint8_t> &host_key)
// {
// 	return true;
// }

// void basic_connection::process_kexinit(ipacket &in, opacket &out, boost::system::error_code &ec)
// {
// 	// if this is a rekey request by the server, send our kexinit packet
// 	if (not m_key_exchange)
// 		rekey();

// 	m_key_exchange->process(in, out, ec);
// }

// void basic_connection::process_service_accept(ipacket &in, opacket &out, boost::system::error_code &ec)
// {
// 	out = msg_userauth_request;
// 	out << m_user << "ssh-connection"
// 		<< "none";
// }

// void basic_connection::process_userauth_success(ipacket &in, opacket &out, boost::system::error_code &ec)
// {
// 	m_authenticated = true;

// 	if (m_delay_compressor)
// 		m_compressor.reset(new compression_helper(true));

// 	if (m_delay_decompressor)
// 		m_decompressor.reset(new compression_helper(false));

// 	m_session_id = m_key_exchange->session_id();

// 	m_key_exchange.reset();

// 	handle_connect_result(boost::system::error_code());
// }

// void basic_connection::process_userauth_failure(ipacket &in, opacket &out, boost::system::error_code &ec)
// {
// 	string s;
// 	bool partial;

// 	in >> s >> partial;

// 	m_private_key_hash.clear();

// 	if (choose_protocol(s, "publickey") == "publickey" and not m_private_keys.empty())
// 	{
// 		out = opacket(msg_userauth_request)
// 				<< m_user << "ssh-connection"
// 				<< "publickey" << false
// 				<< "ssh-rsa" << m_private_keys.front();
// 		m_private_keys.pop_front();
// 		m_auth_state = auth_state_public_key;
// 	}
// 	else if (choose_protocol(s, "keyboard-interactive") == "keyboard-interactive" and m_keyboard_interactive_cb and ++m_password_attempts <= 3)
// 	{
// 		out = opacket(msg_userauth_request)
// 				<< m_user << "ssh-connection"
// 				<< "keyboard-interactive"
// 				<< "en"
// 				<< "";
// 		m_auth_state = auth_state_keyboard_interactive;
// 	}
// 	else if (choose_protocol(s, "password") == "password" and m_request_password_cb and ++m_password_attempts <= 3)
// 		m_request_password_cb();
// 	else
// 		handle_error(error::make_error_code(error::auth_cancelled_by_user));
// }

// void basic_connection::process_userauth_banner(ipacket &in, opacket &out, boost::system::error_code &ec)
// {
// 	string msg, lang;
// 	in >> msg >> lang;

// 	for (auto h : m_connect_handlers)
// 		h->handle_banner(msg, lang);
// }

// void basic_connection::process_userauth_info_request(ipacket &in, opacket &out, boost::system::error_code &ec)
// {
// 	switch (m_auth_state)
// 	{
// 		case auth_state_public_key:
// 		{
// 			out = msg_userauth_request;

// 			string alg;
// 			ipacket blob;

// 			in >> alg >> blob;

// 			out << m_user << "ssh-connection"
// 				<< "publickey" << true << "ssh-rsa" << blob;

// 			opacket session_id;
// 			session_id << m_key_exchange->session_id();

// 			ssh_private_key pk(ssh_agent::instance().get_key(blob));

// 			out << pk.sign(session_id, out);

// 			// store the hash for this private key
// 			m_private_key_hash = pk.get_hash();
// 			break;
// 		}
// 		case auth_state_keyboard_interactive:
// 		{
// 			string name, instruction, language;
// 			int32_t numPrompts = 0;

// 			in >> name >> instruction >> language >> numPrompts;

// 			if (numPrompts == 0)
// 			{
// 				out = msg_userauth_info_response;
// 				out << numPrompts;
// 			}
// 			else
// 			{
// 				vector<prompt> prompts(numPrompts);

// 				for (prompt &p : prompts)
// 					in >> p.str >> p.echo;

// 				if (prompts.empty())
// 				{
// 					prompt p = {"iets", true};
// 					prompts.push_back(p);
// 				}

// 				m_keyboard_interactive_cb(name, language, prompts);
// 			}
// 			break;
// 		}
// 		default:;
// 	}
// }

// void basic_connection::response(const vector<string> &responses)
// {
// 	if (m_auth_state == auth_state_keyboard_interactive)
// 	{
// 		opacket out(msg_userauth_info_response);
// 		out << responses.size();
// 		for (auto r : responses)
// 			out << r;
// 		async_write(move(out));
// 	}
// 	else if (responses.size() == 1)
// 	{
// 		opacket out(msg_userauth_request);
// 		out << m_user << "ssh-connection"
// 			<< "password" << false << responses[0];
// 		async_write(move(out));
// 	}
// 	else
// 		handle_error(error::make_error_code(error::auth_cancelled_by_user));
// }

// struct packet_encryptor
// {
// 	typedef char char_type;
// 	struct category : io::multichar_output_filter_tag, io::flushable_tag
// 	{
// 	};

// 	packet_encryptor(StreamTransformation &cipher,
// 						MessageAuthenticationCode &signer, uint32_t blocksize, uint32_t seq_nr)
// 		: m_cipher(cipher), m_signer(signer), m_blocksize(blocksize), m_flushed(false)
// 	{
// 		for (int i = 3; i >= 0; --i)
// 		{
// 			uint8_t ch = static_cast<uint8_t>(seq_nr >> (i * 8));
// 			m_signer.Update(&ch, 1);
// 		}

// 		m_block.reserve(m_blocksize);
// 	}

// 	template <typename Sink>
// 	streamsize write(Sink &sink, const char *s, streamsize n)
// 	{
// 		streamsize result = 0;

// 		for (streamsize o = 0; o < n; o += m_blocksize)
// 		{
// 			size_t k = n;
// 			if (k > m_blocksize - m_block.size())
// 				k = m_blocksize - m_block.size();

// 			const uint8_t *sp = reinterpret_cast<const uint8_t *>(s);

// 			m_signer.Update(sp, static_cast<size_t>(k));
// 			m_block.insert(m_block.end(), sp, sp + k);

// 			result += k;
// 			s += k;

// 			if (m_block.size() == m_blocksize)
// 			{
// 				vector<uint8_t> block(m_blocksize);
// 				m_cipher.ProcessData(block.data(), m_block.data(), m_blocksize);

// 				for (uint32_t i = 0; i < m_blocksize; ++i)
// 					io::put(sink, block[i]);

// 				m_block.clear();
// 			}
// 		}

// 		return result;
// 	}

// 	template <typename Sink>
// 	bool flush(Sink &sink)
// 	{
// 		if (not m_flushed)
// 		{
// 			assert(m_block.size() == 0);

// 			vector<uint8_t> digest(m_signer.DigestSize());
// 			m_signer.Final(digest.data());
// 			for (size_t i = 0; i < digest.size(); ++i)
// 				io::put(sink, digest[i]);

// 			m_flushed = true;
// 		}

// 		return true;
// 	}

// 	StreamTransformation &m_cipher;
// 	MessageAuthenticationCode &m_signer;
// 	vector<uint8_t> m_block;
// 	uint32_t m_blocksize;
// 	bool m_flushed;
// };

// void basic_connection::async_write_packet_int(opacket &&p, basic_write_op *op)
// {
// 	boost::asio::streambuf *request(new boost::asio::streambuf);

// 	if (m_compressor)
// 	{
// 		boost::system::error_code ec;
// 		p.compress(*m_compressor, ec);

// 		if (ec)
// 		{
// 			(*op)(ec, 0);
// 			delete op;
// 			return;
// 		}
// 	}

// 	{
// 		io::filtering_stream<io::output> out;

// 		if (m_encryptor)
// 			out.push(packet_encryptor(*m_encryptor, *m_signer, m_oblocksize, m_out_seq_nr));

// 		out.push(*request);

// 		p.write(out, m_oblocksize);
// 	}

// 	++m_out_seq_nr;
// 	async_write_int(request, op);
// }



// void basic_connection::process_channel_open(ipacket &in, opacket &out)
// {
// 	channel_ptr c;

// 	string type;

// 	in >> type;

// 	try
// 	{
// 		// if (type == "x11")
// 		// 	c.reset(new x11_channel(shared_from_this()));
// 		// else
// 		if (type == "auth-agent@openssh.com" and m_forward_agent)
// 			c.reset(new ssh_agent_channel(shared_from_this()));
// 	}
// 	catch (...)
// 	{
// 	}

// 	if (c)
// 	{
// 		in.message(msg_channel_open_confirmation);
// 		c->process(in);
// 		m_channels.push_back(c);
// 	}
// 	else
// 	{
// 		uint32_t host_channel_id;
// 		in >> host_channel_id;

// 		const uint32_t SSH_OPEN_UNKNOWN_CHANNEL_TYPE = 3;
// 		out = msg_channel_open_failure;
// 		out << host_channel_id << SSH_OPEN_UNKNOWN_CHANNEL_TYPE << "unsupported channel type"
// 			<< "en";
// 	}
// }

// void basic_connection::process_channel(ipacket &in, opacket &out, boost::system::error_code &ec)
// {
// 	try
// 	{
// 		uint32_t channel_id;
// 		in >> channel_id;

// 		for (channel_ptr c : m_channels)
// 		{
// 			if (c->my_channel_id() == channel_id)
// 			{
// 				c->process(in);
// 				break;
// 			}
// 		}
// 	}
// 	catch (...)
// 	{
// 	}
// }

// // --------------------------------------------------------------------

// void basic_connection::basic_connect_handler::handle_banner(const string &message, const string &lang)
// {
// 	m_opening_channel->banner(message, lang);
// }

// // --------------------------------------------------------------------

// connection::connection(boost::asio::io_service &io_service,
// 						const string &user, const string &host, int16_t port = 22)
// 	: basic_connection(io_service, user), m_io_service(io_service), m_socket(io_service), m_resolver(io_service), m_host(host), m_port(port)
// {
// }

// boost::asio::io_service& connection::get_io_service()
// {
// 	return m_io_service;
// }

// void connection::disconnect()
// {
// 	basic_connection::disconnect();

// 	m_socket.close();
// }

// void connection::start_handshake()
// {
// 	if (not m_socket.is_open())
// 	{
// 		boost::asio::ip::tcp::resolver::query query(m_host, boost::lexical_cast<string>(m_port));
// 		m_resolver.async_resolve(query,
// 									boost::bind(&connection::handle_resolve, this,
// 												boost::asio::placeholders::error, boost::asio::placeholders::iterator));
// 	}
// 	else
// 		basic_connection::start_handshake();
// }

// bool connection::validate_host_key(const std::string &pk_alg, const blob &host_key)
// {
// 	return not m_validate_host_key_cb or m_validate_host_key_cb(m_host, pk_alg, host_key);
// }

// void connection::handle_resolve(const boost::system::error_code &ec, boost::asio::ip::tcp::resolver::iterator endpoint_iterator)
// {
// 	if (ec)
// 		handle_connect_result(ec);
// 	else
// 	{
// 		boost::asio::ip::tcp::endpoint endpoint = *endpoint_iterator;
// 		m_socket.async_connect(endpoint,
// 								boost::bind(&connection::handle_connect, this,
// 											boost::asio::placeholders::error, ++endpoint_iterator));
// 	}
// }

// void connection::handle_connect(const boost::system::error_code &ec, boost::asio::ip::tcp::resolver::iterator endpoint_iterator)
// {
// 	if (not ec)
// 		start_handshake();
// 	else if (endpoint_iterator != boost::asio::ip::tcp::resolver::iterator())
// 	{
// 		// The connection failed. Try the next endpoint in the list.
// 		m_socket.close();
// 		boost::asio::ip::tcp::endpoint endpoint = *endpoint_iterator;
// 		m_socket.async_connect(endpoint,
// 								boost::bind(&connection::handle_connect, this,
// 											boost::asio::placeholders::error, ++endpoint_iterator));
// 	}
// 	else
// 		handle_connect_result(ec);
// }

// void connection::async_write_int(boost::asio::streambuf *request, basic_write_op *op)
// {
// 	auto self(shared_from_this());
// 	boost::asio::async_write(m_socket, *request,
// 								[op, request, self](const boost::system::error_code &ec, size_t bytes_transferred) {
// 									delete request;
// 									(*op)(ec, bytes_transferred);
// 									delete op;
// 								});
// }

// void connection::async_read_version_string()
// {
// 	auto self(shared_from_this());
// 	boost::asio::async_read_until(m_socket, m_response, "\n",
// 									[self, this](const boost::system::error_code &ec, size_t bytes_transferred) {
// 										handle_protocol_version_response(ec, bytes_transferred);
// 									});
// }

// void connection::async_read(uint32_t at_least)
// {
// 	auto self(shared_from_this());
// 	boost::asio::async_read(m_socket, m_response, boost::asio::transfer_at_least(at_least),
// 							[self, this](const boost::system::error_code &ec, size_t bytes_transferred) {
// 								this->received_data(ec);
// 							});
// }

} // namespace pinch
