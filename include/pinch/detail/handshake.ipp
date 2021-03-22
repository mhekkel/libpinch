//        Copyright Maarten L. Hekkelman 2013-2021
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <pinch/channel.hpp>

namespace pinch::detail
{

template <typename Self>
void async_open_connection_impl::operator()(Self &self, boost::system::error_code ec,
	std::size_t bytes_transferred)
{
	auto complete = [&self, conn = this->conn](const boost::system::error_code &ec) {
		conn->handle_error(ec);
		self.complete(ec);
	};

	while (not ec)
	{
		switch (state)
		{
			case state_type::start:
				switch (conn->m_auth_state)
				{
					case connection::none:
						conn->m_auth_state = connection::handshake;
						state = state_type::connect;
						break;

					case connection::handshake:
						state = state_type::wait;
						conn->async_wait(connection_wait_type::open, std::move(self));
						return;

					case connection::authenticated:
						self.complete({});
						break;
				}
				break;

			case state_type::wait:
				self.complete({});
				break;

			case state_type::connect:
				if (not conn->next_layer_is_open())
				{
					state = state_type::open_next;
					conn->async_open_next_layer(std::move(self));
					return;
				}

			case state_type::open_next:
				state = state_type::handshake;
				conn->async_wait(connection::wait_type::write, std::move(self));
				return;

			case state_type::handshake:
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
					self.complete(error::make_error_code(error::protocol_version_not_supported));
					return;
				}

				state = state_type::rekeying;

				kex = std::make_unique<key_exchange>(host_version);

				conn->async_write(kex->init());

				boost::asio::async_read(*conn, response,
					boost::asio::transfer_at_least(8),
					std::move(self));
				return;
			}

			case state_type::rekeying:
			{
				if (not conn->receive_packet(*packet, ec) and not ec)
				{
					boost::asio::async_read(*conn, response,
						boost::asio::transfer_at_least(1),
						std::move(self));
					return;
				}

				if (*packet == msg_newkeys)
				{
					state = state_type::check_host_key;
					conn->async_check_host_key(kex->get_host_key_pk_type(), kex->get_host_key(), std::move(self));
					return;
				}

				opacket out;
				if (kex->process(*packet, out, ec))
				{
					packet->clear();

					if (out)
						conn->async_write(std::move(out));

					continue;
				}
				
				if (not ec)
					ec = error::make_error_code(error::key_exchange_failed);
				break;
			}

			case state_type::check_host_key:
				conn->newkeys(*kex, ec);
				state = state_type::authenticating;
				break;

			case state_type::authenticating:
			{
				opacket out = msg_service_request;
				out << "ssh-userauth";
				conn->async_write(std::move(out));

				// we might not be known yet
				ssh_agent::instance().register_connection(conn);

				// fetch the private keys
				for (auto &pk : ssh_agent::instance())
				{
					opacket blob;
					blob << pk;
					private_keys.push_back(blob);
				}

				state = state_type::authenticating2;
				break;
			}

			case state_type::authenticating2:
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
						else if (choose_protocol(s, "keyboard-interactive") == "keyboard-interactive" and ++m_password_attempts <= 3)
						{
							out = opacket(msg_userauth_request)
									<< user << "ssh-connection"
									<< "keyboard-interactive"
									<< "en"
									<< "";
							auth_state = auth_state_type::keyboard_interactive;
						}
						else if (choose_protocol(s, "password") == "password" and ++m_password_attempts <= 3)
						{
							state = state_type::password;
							// conn->async_provide_password(std::move(self));
						}
						else
						{
							auth_state = auth_state_type::error;
							ec = error::make_error_code(error::no_more_auth_methods_available);
						}

						break;
					}

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
					complete(ec);
					return;
				}

				if (out)
					conn->async_write(std::move(out));

				packet->clear();
				break;
			}

			case state_type::password:
				auto password = conn->provide_password();
				if (password.empty())
				{
					m_password_attempts = 4;
					ec = error::make_error_code(error::auth_cancelled_by_user);
				}
				else
				{
					auth_state = auth_state_type::password;
					auto out = opacket(msg_userauth_request)
							<< conn->m_user << "ssh-connection"
							<< "password" << false << password;
				}
				break;
		}
	}

	complete(ec);
}

inline void async_open_connection_impl::async_open_connection_impl::process_userauth_failure(ipacket &in, opacket &out, boost::system::error_code &ec)
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
	else if (choose_protocol(s, "keyboard-interactive") == "keyboard-interactive" and ++m_password_attempts <= 3)
	{
		out = opacket(msg_userauth_request)
				<< user << "ssh-connection"
				<< "keyboard-interactive"
				<< "en"
				<< "";
		auth_state = auth_state_type::keyboard_interactive;
	}
	else if (choose_protocol(s, "password") == "password" and ++m_password_attempts <= 3)
	{
		auto password = conn->provide_password();

		if (password.empty())
		{
			m_password_attempts = 4;
			ec = error::make_error_code(error::auth_cancelled_by_user);
		}
		else
		{
			auth_state = auth_state_type::password;
			out = opacket(msg_userauth_request)
					<< conn->m_user << "ssh-connection"
					<< "password" << false << password;
		}
	}
	else
	{
		auth_state = auth_state_type::error;
		ec = error::make_error_code(error::no_more_auth_methods_available);
	}
}

inline void async_open_connection_impl::process_userauth_info_request(ipacket &in, opacket &out, boost::system::error_code &ec)
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

				for (auto &p : prompts)
					in >> p.str >> p.echo;

				auto replies = conn->provide_credentials(name, instruction, language, prompts);

				if (replies.empty())
				{
					m_password_attempts = 4;
					ec = error::make_error_code(error::auth_cancelled_by_user);
				}
				else
				{
					out = opacket(msg_userauth_info_response)
							<< replies.size();

					for (auto &r : replies)
						out << r;
				}
			}
			break;
		}
		default:
			ec = make_error_code(error::protocol_error);
	}
}

} // namespace pinch::detail
