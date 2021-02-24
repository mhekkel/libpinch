//#define BOOST_ASIO_ENABLE_HANDLER_TRACKING

#include <boost/asio.hpp>

#include <iostream>
#include <deque>

#include <type_traits>

#include <boost/algorithm/string.hpp>

#include "assh/connection.hpp"
#include "assh/connection_pool.hpp"
#include "assh/channel.hpp"
#include "assh/terminal_channel.hpp"

namespace ba = boost::algorithm;

namespace assh
{

template<typename Stream>
class connection2 : public std::enable_shared_from_this<connection2<Stream>>
{
  public:

	template<typename Arg>
	connection2(Arg&& arg, const std::string& user)
		: m_next_layer(std::forward<Arg>(arg))
		, m_user(user)
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

	template<typename Handler>
	auto async_handshake(Handler&& handler)
	{
		enum { start, wrote_version, reading };

		auto conn = this->shared_from_this();
		auto request = std::make_unique<boost::asio::streambuf>();

		return boost::asio::async_compose<Handler, void(boost::system::error_code)>(
			[
				&socket = m_next_layer,
				conn,
				state = start,
				request = std::move(request),
				&response = m_response,
				&host_version = m_host_version
			]
			(auto& self, const boost::system::error_code ec = {}, std::size_t bytes_transferred = 0) mutable
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

							conn->rekey();
							conn->received_data({});
							break;
						}
					}
				}

				self.complete(ec);
			}, handler, m_next_layer
		);
	}

	void rekey()
	{
		m_key_exchange.reset(new key_exchange(m_host_version, m_session_id));
		async_write(m_key_exchange->init());
	}

	void async_write(opacket&& out)
	{
		async_write(std::move(out), [this](boost::system::error_code& ec)
		{
			if (ec)
				this->handle_error(ec);
		});
	}

	template<typename Handler>
	auto async_write(opacket&& out, Handler&& handler)
	{
		auto request = std::make_unique<boost::asio::streambuf>();

		if (m_compressor)
		{
			boost::system::error_code ec;
			p.compress(*m_compressor, ec);

			if (ec)
			{
				handler(ec, 0);
				return;
			}
		}

		{
			io::filtering_stream<io::output> out;

			if (m_encryptor)
				out.push(packet_encryptor(*m_encryptor, *m_signer, m_oblocksize, m_out_seq_nr));

			out.push(*request);

			p.write(out, m_oblocksize);
		}

		++m_out_seq_nr;
		async_write_int(request, op);

	}

	void async_read(uint32_t at_least)
	{
		async_read(at_least, [this](boost::system::error_code& ec)
		{
			if (ec)
				this->handle_error(ec);
		});
	}

	template<typename Handler>
	auto async_read(uint32_t at_least, Handler&& handler)
	{

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

			m_auth_state = auth_state::connected;
			// handle_connect_result(ec);
		}
	}

  private:

	void received_data(const boost::system::error_code& ec);

	void process_packet(ipacket &in);

	void reset()
	{
		// m_authenticated = false;
		m_auth_state = auth_state::none;
		m_private_key_hash.clear();
		m_key_exchange.reset();
		m_session_id.clear();
		m_packet.clear();
		m_encryptor.reset(nullptr);
		m_decryptor.reset(nullptr);
		m_signer.reset(nullptr);
		m_verifier.reset(nullptr);
		m_compressor.reset(nullptr);
		m_decompressor.reset(nullptr);
		m_delay_decompressor = m_delay_compressor = false;
		m_password_attempts = 0;
		m_in_seq_nr = m_out_seq_nr = 0;
		m_iblocksize = m_oblocksize = 8;
		m_last_io = 0;
	}

	Stream m_next_layer;
	std::string m_user;


	enum class auth_state
	{
		none,
		connecting,
		public_key,
		keyboard_interactive,
		password,
		connected
	};

	auth_state m_auth_state = auth_state::none;
	std::string m_host_version;
	std::unique_ptr<key_exchange> m_key_exchange;

	// connect_handler_list m_connect_handlers;

	std::vector<uint8_t> /*m_my_payload, m_host_payload, */m_session_id;
	int64_t m_last_io;
	uint32_t m_password_attempts;
	std::vector<uint8_t> m_private_key_hash;
	uint32_t m_in_seq_nr, m_out_seq_nr;
	ipacket m_packet;
	uint32_t m_iblocksize, m_oblocksize;
	boost::asio::streambuf m_response;

	// validate_callback_type m_validate_host_key_cb;
	// password_callback_type m_request_password_cb;
	// keyboard_interactive_callback_type m_keyboard_interactive_cb;

	std::unique_ptr<CryptoPP::StreamTransformation> m_decryptor;
	std::unique_ptr<CryptoPP::StreamTransformation> m_encryptor;
	std::unique_ptr<CryptoPP::MessageAuthenticationCode> m_signer;
	std::unique_ptr<CryptoPP::MessageAuthenticationCode> m_verifier;

	std::unique_ptr<compression_helper> m_compressor;
	std::unique_ptr<compression_helper> m_decompressor;
	bool m_delay_compressor, m_delay_decompressor;

	std::deque<opacket> m_private_keys;

	std::list<channel_ptr> m_channels;
	bool m_forward_agent;
	port_forward_listener *m_port_forwarder;

	std::string m_alg_kex,
		m_alg_enc_c2s, m_alg_ver_c2s, m_alg_cmp_c2s,
		m_alg_enc_s2c, m_alg_ver_s2c, m_alg_cmp_s2c;
};

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
	if (m_auth_state == auth_state::none)
		return;

	try
	{
		while (m_response.size() >= m_iblocksize)
		{
			if (not m_packet.complete())
			{
				std::vector<uint8_t> block(m_iblocksize);
				m_response.sgetn(reinterpret_cast<char *>(&block[0]), m_iblocksize);

				if (m_decryptor)
				{
					std::vector<uint8_t> data(m_iblocksize);
					m_decryptor->ProcessData(&data[0], &block[0], m_iblocksize);
					std::swap(data, block);
				}

				if (m_verifier)
				{
					if (m_packet.empty())
					{
						for (int32_t i = 3; i >= 0; --i)
						{
							uint8_t b = m_in_seq_nr >> (i * 8);
							m_verifier->Update(&b, 1);
						}
					}

					m_verifier->Update(&block[0], block.size());
				}

				m_packet.append(block);
			}

			if (m_packet.complete())
			{
				if (m_verifier)
				{
					if (m_response.size() < m_verifier->DigestSize())
						break;

					std::vector<uint8_t> digest(m_verifier->DigestSize());
					m_response.sgetn(reinterpret_cast<char *>(&digest[0]), m_verifier->DigestSize());

					if (not m_verifier->Verify(&digest[0]))
					{
						handle_error(error::make_error_code(error::mac_error));
						return;
					}
				}

				if (m_decompressor)
				{
					boost::system::error_code ec;
					m_packet.decompress(*m_decompressor, ec);
					if (ec)
					{
						handle_error(ec);
						break;
					}
				}

				process_packet(m_packet);

				m_packet.clear();
				++m_in_seq_nr;
			}
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

		async_read(at_least);
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

	bool handled = false;

	if (m_key_exchange)
		handled = m_key_exchange->process(in, out, ec);

	if (not handled)
	{
		handled = true;

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

			// case msg_service_accept:
			// 	process_service_accept(in, out, ec);
			// 	break;

			// case msg_kexinit:
			// 	process_kexinit(in, out, ec);
			// 	break;

			// case msg_newkeys:
			// 	process_newkeys(in, out, ec);
			// 	break;

			// case msg_userauth_success:
			// 	process_userauth_success(in, out, ec);
			// 	break;
			// case msg_userauth_failure:
			// 	process_userauth_failure(in, out, ec);
			// 	break;
			// case msg_userauth_banner:
			// 	process_userauth_banner(in, out, ec);
			// 	break;
			// case msg_userauth_info_request:
			// 	process_userauth_info_request(in, out, ec);
			// 	break;

			// // channel
			// case msg_channel_open:
			// 	if (m_authenticated)
			// 		process_channel_open(in, out);
			// 	break;
			// case msg_channel_open_confirmation:
			// case msg_channel_open_failure:
			// case msg_channel_window_adjust:
			// case msg_channel_data:
			// case msg_channel_extended_data:
			// case msg_channel_eof:
			// case msg_channel_close:
			// case msg_channel_request:
			// case msg_channel_success:
			// case msg_channel_failure:
			// 	if (m_authenticated)
			// 		process_channel(in, out, ec);
			// 	break;

			default:
			{
				opacket out(msg_unimplemented);
				out << (uint32_t)m_in_seq_nr;
				async_write(std::move(out));
				break;
			}
		}
	}

	if (ec)
		// handle_connect_result(ec);
		handle_error(ec);

	if (not out.empty())
		async_write(std::move(out));
}

}



int main() {
	using boost::asio::ip::tcp;

	boost::asio::io_context io_context;

	auto conn = std::make_shared<assh::connection2<boost::asio::ip::tcp::socket>>(io_context, "maarten");

	tcp::resolver resolver(io_context);
	tcp::resolver::results_type endpoints = resolver.resolve("localhost", "ssh");

	boost::asio::connect(conn->lowest_layer(), endpoints);
	conn->async_handshake([](boost::system::error_code ec)
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