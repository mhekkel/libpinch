//#define BOOST_ASIO_ENABLE_HANDLER_TRACKING

#include <boost/asio.hpp>

#include <iostream>
#include <deque>

#include <type_traits>

#include <boost/algorithm/string.hpp>
#include <boost/iostreams/filtering_stream.hpp>

#include <cryptopp/cryptlib.h>
#include <cryptopp/gfpcrypt.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/aes.h>
#include <cryptopp/des.h>
#include <cryptopp/ripemd.h>
#include <cryptopp/blowfish.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/factory.h>
#include <cryptopp/modes.h>

#include "assh/connection.hpp"
#include "assh/connection_pool.hpp"
#include "assh/channel.hpp"
#include "assh/terminal_channel.hpp"
#include "assh/ssh_agent.hpp"

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



struct packet_encryptor
{
	typedef char char_type;
	struct category : io::multichar_output_filter_tag, io::flushable_tag
	{
	};

	packet_encryptor(CryptoPP::StreamTransformation &cipher,
						CryptoPP::MessageAuthenticationCode &signer, uint32_t blocksize, uint32_t seq_nr)
		: m_cipher(cipher), m_signer(signer), m_blocksize(blocksize), m_flushed(false)
	{
		for (int i = 3; i >= 0; --i)
		{
			uint8_t ch = static_cast<uint8_t>(seq_nr >> (i * 8));
			m_signer.Update(&ch, 1);
		}

		m_block.reserve(m_blocksize);
	}

	template <typename Sink>
	std::streamsize write(Sink &sink, const char *s, std::streamsize n)
	{
		std::streamsize result = 0;

		for (std::streamsize o = 0; o < n; o += m_blocksize)
		{
			size_t k = n;
			if (k > m_blocksize - m_block.size())
				k = m_blocksize - m_block.size();

			const uint8_t *sp = reinterpret_cast<const uint8_t *>(s);

			m_signer.Update(sp, static_cast<size_t>(k));
			m_block.insert(m_block.end(), sp, sp + k);

			result += k;
			s += k;

			if (m_block.size() == m_blocksize)
			{
				std::vector<uint8_t> block(m_blocksize);
				m_cipher.ProcessData(block.data(), m_block.data(), m_blocksize);

				for (uint32_t i = 0; i < m_blocksize; ++i)
					io::put(sink, block[i]);

				m_block.clear();
			}
		}

		return result;
	}

	template <typename Sink>
	bool flush(Sink &sink)
	{
		if (not m_flushed)
		{
			assert(m_block.size() == 0);

			std::vector<uint8_t> digest(m_signer.DigestSize());
			m_signer.Final(digest.data());
			for (size_t i = 0; i < digest.size(); ++i)
				io::put(sink, digest[i]);

			m_flushed = true;
		}

		return true;
	}

	CryptoPP::StreamTransformation &m_cipher;
	CryptoPP::MessageAuthenticationCode &m_signer;
	std::vector<uint8_t> m_block;
	uint32_t m_blocksize;
	bool m_flushed;
};

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
	typedef std::function<bool(const std::string &, const std::string &, const std::vector<uint8_t> &)>
		validate_callback_type;

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
				out.push(detail::packet_encryptor(*m_encryptor, *m_signer, m_oblocksize, m_out_seq_nr));
			out.push(*request);

			p.write(out, m_oblocksize);
		}

		++m_out_seq_nr;
		return async_write(std::move(request), std::move(handler));
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
	auto async_read_packet(Handler&& handler)
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

				while (m_response.size() >= m_iblocksize)
				{
					if (not packet->complete())
					{
						std::vector<uint8_t> block(m_iblocksize);
						m_response.sgetn(reinterpret_cast<char *>(block.data()), m_iblocksize);

						if (m_decryptor)
						{
							std::vector<uint8_t> data(m_iblocksize);
							m_decryptor->ProcessData(data.data(), block.data(), m_iblocksize);
							std::swap(data, block);
						}

						if (m_verifier)
						{
							if (packet->empty())
							{
								for (int32_t i = 3; i >= 0; --i)
								{
									uint8_t b = m_in_seq_nr >> (i * 8);
									m_verifier->Update(&b, 1);
								}
							}

							m_verifier->Update(block.data(), block.size());
						}

						packet->append(block);
					}

					if (packet->complete())
					{
						if (m_verifier)
						{
							if (m_response.size() < m_verifier->DigestSize())
								break;

							std::vector<uint8_t> digest(m_verifier->DigestSize());
							m_response.sgetn(reinterpret_cast<char *>(digest.data()), m_verifier->DigestSize());

							if (not m_verifier->Verify(digest.data()))
							{
								handle_error(error::make_error_code(error::mac_error));
								return;
							}
						}

						if (m_decompressor)
						{
							boost::system::error_code ec;
							packet->decompress(*m_decompressor, ec);
							if (ec)
							{
								handle_error(ec);
								break;
							}
						}

						++m_in_seq_nr;

						self.complete({}, *packet);
						return;
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

				boost::asio::async_read(socket, m_response, boost::asio::transfer_at_least(at_least), std::move(self));
			}
		);
	}

  private:

	bool receive_packet(ipacket& packet, boost::system::error_code& ec)
	{
		bool result = false;
		ec = {};

		while (m_response.size() >= m_iblocksize)
		{
			if (not packet.complete())
			{
				std::vector<uint8_t> block(m_iblocksize);
				m_response.sgetn(reinterpret_cast<char *>(block.data()), m_iblocksize);

				if (m_decryptor)
				{
					std::vector<uint8_t> data(m_iblocksize);
					m_decryptor->ProcessData(data.data(), block.data(), m_iblocksize);
					std::swap(data, block);
				}

				if (m_verifier)
				{
					if (packet.empty())
					{
						for (int32_t i = 3; i >= 0; --i)
						{
							uint8_t b = m_in_seq_nr >> (i * 8);
							m_verifier->Update(&b, 1);
						}
					}

					m_verifier->Update(block.data(), block.size());
				}

				packet.append(block);
			}

			if (packet.complete())
			{
				if (m_verifier)
				{
					if (m_response.size() < m_verifier->DigestSize())
						break;

					std::vector<uint8_t> digest(m_verifier->DigestSize());
					m_response.sgetn(reinterpret_cast<char *>(digest.data()), m_verifier->DigestSize());

					if (not m_verifier->Verify(digest.data()))
					{
						ec = error::make_error_code(error::mac_error);
						return false;
					}
				}

				if (m_decompressor)
				{
					boost::system::error_code ec;
					packet.decompress(*m_decompressor, ec);
					if (ec)
					{
						handle_error(ec);
						break;
					}
				}

				++m_in_seq_nr;
				result = true;
				break;
			}
		}

		if (result)
		{
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
		m_encryptor.reset(nullptr);
		m_decryptor.reset(nullptr);
		m_signer.reset(nullptr);
		m_verifier.reset(nullptr);
		m_compressor.reset(nullptr);
		m_decompressor.reset(nullptr);
		m_delay_decompressor = m_delay_compressor = false;
		m_in_seq_nr = m_out_seq_nr = 0;
		m_iblocksize = m_oblocksize = 8;
		m_last_io = 0;
	}

	Stream m_next_layer;
	std::string m_user;

	detail::auth_state_type m_auth_state = detail::auth_state_type::none;
	std::string m_host_version;
	std::vector<uint8_t> m_session_id;

	// connect_handler_list m_connect_handlers;

	int64_t m_last_io;
	// uint32_t m_password_attempts;
	std::vector<uint8_t> m_private_key_hash;
	uint32_t m_in_seq_nr, m_out_seq_nr;
	ipacket m_packet;
	uint32_t m_iblocksize, m_oblocksize;
	boost::asio::streambuf m_response;

	validate_callback_type m_validate_host_key_cb;
	password_callback_type m_request_password_cb;
	keyboard_interactive_callback_type m_keyboard_interactive_cb;

	std::unique_ptr<CryptoPP::StreamTransformation> m_decryptor;
	std::unique_ptr<CryptoPP::StreamTransformation> m_encryptor;
	std::unique_ptr<CryptoPP::MessageAuthenticationCode> m_signer;
	std::unique_ptr<CryptoPP::MessageAuthenticationCode> m_verifier;

	std::unique_ptr<compression_helper> m_compressor;
	std::unique_ptr<compression_helper> m_decompressor;
	bool m_delay_compressor, m_delay_decompressor;

	std::list<channel_ptr> m_channels;
	bool m_forward_agent;
	port_forward_listener *m_port_forwarder;

	std::string m_alg_kex,
		m_alg_enc_c2s = kEncryptionAlgorithms, m_alg_ver_c2s = kMacAlgorithms, m_alg_cmp_c2s = kCompressionAlgorithms,
		m_alg_enc_s2c = kEncryptionAlgorithms, m_alg_ver_s2c = kMacAlgorithms, m_alg_cmp_s2c = kCompressionAlgorithms;
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
	if (m_auth_state == detail::auth_state_type::none)
		return;

	try
	{
		while (m_response.size() >= m_iblocksize)
		{
			if (not m_packet.complete())
			{
				std::vector<uint8_t> block(m_iblocksize);
				m_response.sgetn(reinterpret_cast<char *>(block.data()), m_iblocksize);

				if (m_decryptor)
				{
					std::vector<uint8_t> data(m_iblocksize);
					m_decryptor->ProcessData(data.data(), block.data(), m_iblocksize);
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

					m_verifier->Update(block.data(), block.size());
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
					m_response.sgetn(reinterpret_cast<char *>(digest.data()), m_verifier->DigestSize());

					if (not m_verifier->Verify(digest.data()))
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
			out << (uint32_t)m_in_seq_nr;
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
void connection2<Stream>::newkeys(key_exchange& kex, boost::system::error_code &ec)
{
	ipacket payload = kex.host_payload();

	std::string key_exchange_alg, server_host_key_alg, encryption_alg_c2s, encryption_alg_s2c,
		MAC_alg_c2s, MAC_alg_s2c, compression_alg_c2s, compression_alg_s2c;

	payload.skip(16);
	payload >> key_exchange_alg >> server_host_key_alg >> encryption_alg_c2s >> encryption_alg_s2c >> MAC_alg_c2s >> MAC_alg_s2c >> compression_alg_c2s >> compression_alg_s2c;

	// Client to server encryption
	std::string protocol = choose_protocol(encryption_alg_c2s, m_alg_enc_c2s);

	const uint8_t *key = kex.key(key_exchange::C);
	const uint8_t *iv = kex.key(key_exchange::A);

	if (protocol == "3des-cbc")
		m_encryptor.reset(new CryptoPP::CBC_Mode<CryptoPP::DES_EDE3>::Encryption(key, 24, iv));
	else if (protocol == "blowfish-cbc")
		m_encryptor.reset(new CryptoPP::CBC_Mode<CryptoPP::Blowfish>::Encryption(key, 16, iv));
	else if (protocol == "aes128-cbc")
		m_encryptor.reset(new CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption(key, 16, iv));
	else if (protocol == "aes192-cbc")
		m_encryptor.reset(new CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption(key, 24, iv));
	else if (protocol == "aes256-cbc")
		m_encryptor.reset(new CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption(key, 32, iv));
	else if (protocol == "aes128-ctr")
		m_encryptor.reset(new CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption(key, 16, iv));
	else if (protocol == "aes192-ctr")
		m_encryptor.reset(new CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption(key, 24, iv));
	else if (protocol == "aes256-ctr")
		m_encryptor.reset(new CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption(key, 32, iv));

	// Server to client encryption
	protocol = choose_protocol(encryption_alg_s2c, m_alg_enc_s2c);

	key = kex.key(key_exchange::D);
	iv = kex.key(key_exchange::B);

	if (protocol == "3des-cbc")
		m_decryptor.reset(new CryptoPP::CBC_Mode<CryptoPP::DES_EDE3>::Decryption(key, 24, iv));
	else if (protocol == "blowfish-cbc")
		m_decryptor.reset(new CryptoPP::CBC_Mode<CryptoPP::Blowfish>::Decryption(key, 16, iv));
	else if (protocol == "aes128-cbc")
		m_decryptor.reset(new CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption(key, 16, iv));
	else if (protocol == "aes192-cbc")
		m_decryptor.reset(new CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption(key, 24, iv));
	else if (protocol == "aes256-cbc")
		m_decryptor.reset(new CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption(key, 32, iv));
	else if (protocol == "aes128-ctr")
		m_decryptor.reset(new CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption(key, 16, iv));
	else if (protocol == "aes192-ctr")
		m_decryptor.reset(new CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption(key, 24, iv));
	else if (protocol == "aes256-ctr")
		m_decryptor.reset(new CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption(key, 32, iv));

	// Client To Server verification
	protocol = choose_protocol(MAC_alg_c2s, m_alg_ver_c2s);
	iv = kex.key(key_exchange::E);

	if (protocol == "hmac-sha2-512")
		m_signer.reset(new CryptoPP::HMAC<CryptoPP::SHA512>(iv, 64));
	else if (protocol == "hmac-sha2-256")
		m_signer.reset(new CryptoPP::HMAC<CryptoPP::SHA256>(iv, 32));
	else if (protocol == "hmac-ripemd160")
		m_signer.reset(new CryptoPP::HMAC<CryptoPP::RIPEMD160>(iv, 20));
	else if (protocol == "hmac-sha1")
		m_signer.reset(new CryptoPP::HMAC<CryptoPP::SHA1>(iv, 20));
	else
		assert(false);

	// Server to Client verification

	protocol = choose_protocol(MAC_alg_s2c, m_alg_ver_s2c);
	iv = kex.key(key_exchange::F);

	if (protocol == "hmac-sha2-512")
		m_verifier.reset(new CryptoPP::HMAC<CryptoPP::SHA512>(iv, 64));
	else if (protocol == "hmac-sha2-256")
		m_verifier.reset(new CryptoPP::HMAC<CryptoPP::SHA256>(iv, 32));
	else if (protocol == "hmac-ripemd160")
		m_verifier.reset(new CryptoPP::HMAC<CryptoPP::RIPEMD160>(iv, 20));
	else if (protocol == "hmac-sha1")
		m_verifier.reset(new CryptoPP::HMAC<CryptoPP::SHA1>(iv, 20));
	else
		assert(false);

	// Client to Server compression
	protocol = choose_protocol(compression_alg_c2s, m_alg_cmp_c2s);
	if ((not m_compressor and protocol == "zlib") or (m_auth_state == detail::auth_state_type::authenticated and protocol == "zlib@openssh.com"))
		m_compressor.reset(new compression_helper(true));
	else if (protocol == "zlib@openssh.com")
		m_delay_compressor = true;

	// Server to Client compression
	protocol = choose_protocol(compression_alg_s2c, m_alg_cmp_s2c);
	if ((not m_decompressor and protocol == "zlib") or (m_auth_state == detail::auth_state_type::authenticated and protocol == "zlib@openssh.com"))
		m_decompressor.reset(new compression_helper(false));
	else if (protocol == "zlib@openssh.com")
		m_delay_decompressor = true;

	if (m_decryptor)
	{
		m_iblocksize = m_decryptor->OptimalBlockSize();
		m_oblocksize = m_encryptor->OptimalBlockSize();
	}
}

template<typename Stream>
void connection2<Stream>::userauth_success(const std::string& host_version, const std::vector<uint8_t>& session_id)
{
	m_auth_state = detail::auth_state_type::authenticated;

	if (m_delay_compressor)
		m_compressor.reset(new compression_helper(true));

	if (m_delay_decompressor)
		m_decompressor.reset(new compression_helper(false));

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