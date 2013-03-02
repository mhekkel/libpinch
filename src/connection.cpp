//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <assh/config.hpp>

#include <iostream>

#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/iostreams/filtering_stream.hpp>
#include <boost/iostreams/flush.hpp>
#include <boost/foreach.hpp>
#define foreach BOOST_FOREACH
#include <boost/lexical_cast.hpp>

#include <cryptopp/gfpcrypt.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/aes.h>
#include <cryptopp/des.h>
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>
#include <cryptopp/blowfish.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/factory.h>
#include <cryptopp/modes.h>

#include <assh/connection.hpp>
#include <assh/channel.hpp>
#include <assh/hash.hpp>
#include <assh/ssh_agent.hpp>
#include <assh/x11_channel.hpp>
#include <assh/key_exchange.hpp>
#include <assh/error.hpp>

using namespace std;
using namespace CryptoPP;

namespace io = boost::iostreams;
namespace ba = boost::algorithm;

namespace assh
{

// --------------------------------------------------------------------

AutoSeededRandomPool	rng;

const string
	kSSHVersionString("SSH-2.0-libassh");

const string
	kKeyExchangeAlgorithms_("diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1"),
	kServerHostKeyAlgorithms_("ssh-rsa,ssh-dss"),
	kEncryptionAlgorithms_("aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc,blowfish-cbc,3des-cbc"),
	kMacAlgorithms_("hmac-sha1,hmac-md5"),
	kCompressionAlgorithms_("zlib@openssh.com,zlib,none");

string choose_protocol(const string& server, const string& client)
{
	string result;
	bool found = false;

	typedef ba::split_iterator<string::const_iterator> split_iter_type;
	split_iter_type c = ba::make_split_iterator(client, ba::first_finder(",", ba::is_equal()));
	split_iter_type s = ba::make_split_iterator(server, ba::first_finder(",", ba::is_equal()));
	
	for (split_iter_type ci = c; not found and ci != split_iter_type(); ++ci)
	{
		for (split_iter_type si = s; not found and si != split_iter_type(); ++si)
		{
			if (*ci == *si)
			{
				result = boost::copy_range<string>(*ci);
				found = true;
			}
		}
	}

	return result;
}

// --------------------------------------------------------------------

basic_connection::basic_connection(boost::asio::io_service& io_service, const string& user)
	: m_io_service(io_service)
	, m_user(user)
	, m_authenticated(false)
	, m_auth_state(auth_state_none)
	, m_key_exchange(nullptr)
	, m_forward_agent(false)
	, m_alg_kex(kKeyExchangeAlgorithms_)
	, m_alg_enc_c2s(kEncryptionAlgorithms_)
	, m_alg_ver_c2s(kMacAlgorithms_)
	, m_alg_cmp_c2s(kCompressionAlgorithms_)
	, m_alg_enc_s2c(kEncryptionAlgorithms_) 
	, m_alg_ver_s2c(kMacAlgorithms_)        
	, m_alg_cmp_s2c(kCompressionAlgorithms_)
{
}

basic_connection::~basic_connection()
{
	delete m_key_exchange;
}

void basic_connection::set_algorithm(algorithm alg, direction dir, const string& preferred)
{
	switch (alg)
	{
		case keyexchange:
			m_alg_kex = preferred;
			break;

		case encryption:
			if (dir == client2server)
				m_alg_enc_c2s = preferred;
			else
				m_alg_enc_s2c = preferred;
			break;

		case verification:
			if (dir == client2server)
				m_alg_ver_c2s = preferred;
			else
				m_alg_ver_s2c = preferred;
			break;

		case compression:
			if (dir == client2server)
				m_alg_cmp_c2s = preferred;
			else
				m_alg_cmp_s2c = preferred;
			break;
	}
}

void basic_connection::set_validate_callback(const validate_callback_type& cb)
{
	m_validate_host_key_cb = cb;
}

void basic_connection::set_password_callback(const password_callback_type& cb)
{
	m_request_password_cb = cb;
}

void basic_connection::disconnect()
{
	m_authenticated = false;
	m_auth_state = auth_state_none;
	
	m_packet.clear();
	m_encryptor.reset(nullptr);
	m_decryptor.reset(nullptr);
	m_signer.reset(nullptr);
	m_verifier.reset(nullptr);
	m_compressor.reset(nullptr);
	m_decompressor.reset(nullptr);
	m_delay_decompressor = m_delay_compressor = false;
	
	// copy the list since calling Close will change it
	list<channel*> channels(m_channels);
	for_each(channels.begin(), channels.end(), [](channel* c) { c->close(); });
}

void basic_connection::forward_agent(bool forward)
{
	m_forward_agent = forward;
}

string basic_connection::get_connection_parameters(direction dir) const
{
	string result;

	ipacket payload(&m_host_payload[0], m_host_payload.size());

	string key_exchange_alg, server_host_key_alg, encryption_alg_c2s, encryption_alg_s2c,
		MAC_alg_c2s, MAC_alg_s2c, compression_alg_c2s, compression_alg_s2c;
	
	payload.skip(16);
	payload	>> key_exchange_alg
			>> server_host_key_alg
			>> encryption_alg_c2s
			>> encryption_alg_s2c
			>> MAC_alg_c2s
			>> MAC_alg_s2c
			>> compression_alg_c2s
			>> compression_alg_s2c;

	if (dir == client2server)
	{
		result = choose_protocol(encryption_alg_c2s, m_alg_enc_c2s) + '/' +
				 choose_protocol(MAC_alg_c2s, m_alg_ver_c2s);
		
		string compression = choose_protocol(compression_alg_c2s, m_alg_cmp_c2s);
		if (compression != "none")
			result = result + '/' + compression;
	}
	else
	{
		result = choose_protocol(encryption_alg_s2c, m_alg_enc_s2c) + '/' +
				 choose_protocol(MAC_alg_s2c, m_alg_ver_s2c);
		
		string compression = choose_protocol(compression_alg_s2c, m_alg_cmp_s2c);
		if (compression != "none")
			result = result + '/' + compression;
	}
	
	return result;
}

string basic_connection::get_key_exchange_algoritm() const
{
	string result;

	ipacket payload(&m_host_payload[0], m_host_payload.size());

	string key_exchange_alg;
	
	payload.skip(16);
	payload	>> key_exchange_alg;

	return choose_protocol(key_exchange_alg, m_alg_kex);
}

void basic_connection::handle_connect_result(const boost::system::error_code& ec)
{
	if (ec)
		m_auth_state = auth_state_none;
	else
		m_auth_state = auth_state_connected;
	
	for_each(m_connect_handlers.begin(), m_connect_handlers.end(),
		[this, &ec](basic_connect_handler* h)
		{
			try { h->handle_connect(ec, m_io_service); } catch (...) {}
			delete h;
		});
	
	m_connect_handlers.clear();

	if (ec)
		disconnect();
}

void basic_connection::start_handshake()
{
	if (m_auth_state == auth_state_none)
	{
		m_authenticated = false;
		m_auth_state = auth_state_connecting;

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
		
		boost::asio::streambuf* request(new boost::asio::streambuf);
		ostream out(request);
		out << kSSHVersionString << "\r\n";
	
		async_write(request, [this](const boost::system::error_code& ec, size_t bytes_transferred)
		{
			handle_protocol_version_request(ec, bytes_transferred);
		});
	}
}

void basic_connection::handle_protocol_version_request(const boost::system::error_code& ec, size_t)
{
	if (ec)
		handle_connect_result(ec);
	else
		async_read_version_string();
}

void basic_connection::handle_protocol_version_response(const boost::system::error_code& ec, size_t)
{
	if (ec)
		handle_connect_result(ec);
	else
	{
		istream response_stream(&m_response);
		
		getline(response_stream, m_host_version);
		ba::trim_right(m_host_version);
		
		if (ba::starts_with(m_host_version, "SSH-2.0"))
		{
			opacket out(msg_kexinit);
			
			for (uint32 i = 0; i < 16; ++i)
				out << rng.GenerateByte();
			
			out << m_alg_kex
				<< kServerHostKeyAlgorithms_
				<< m_alg_enc_c2s
				<< m_alg_enc_s2c
				<< m_alg_ver_c2s
				<< m_alg_ver_s2c
				<< m_alg_cmp_c2s
				<< m_alg_cmp_s2c
				<< ""
				<< ""
				<< false
				<< uint32(0);
			
			m_my_payload = out;
			
			async_write(move(out), [this](const boost::system::error_code& ec, size_t bytes_transferred)
			{
				if (ec)
					handle_connect_result(ec);
			});
			
			// start read loop
			received_data(boost::system::error_code());
		}
		else
			handle_connect_result(error::make_error_code(error::protocol_version_not_supported));
	}
}

// the read loop, this routine keeps calling itself until an error condition is met
void basic_connection::received_data(const boost::system::error_code& ec)
{
	if (ec)
	{
		full_stop(ec);
		return;
	}

	// don't process data at all if we're no longer willing
	if (m_auth_state == auth_state_none)
		return;

	while (m_response.size() >= m_iblocksize)
	{
		if (not m_packet.complete())
		{
			vector<uint8> block(m_iblocksize);
			m_response.sgetn(reinterpret_cast<char*>(&block[0]), m_iblocksize);

			if (m_decryptor)
			{
				vector<uint8> data(m_iblocksize);
				m_decryptor->ProcessData(&data[0], &block[0], m_iblocksize);
				swap(data, block);
			}

			if (m_verifier)
			{
				if (m_packet.empty())
				{
					for (int32 i = 3; i >= 0; --i)
					{
						uint8 b = m_in_seq_nr >> (i * 8);
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
				
				vector<uint8> digest(m_verifier->DigestSize());
				m_response.sgetn(reinterpret_cast<char*>(&digest[0]), m_verifier->DigestSize());
				
				if (not m_verifier->Verify(&digest[0]))
				{
					full_stop(error::make_error_code(error::mac_error));
					return;
				}
			}
			
			if (m_decompressor)
			{
				boost::system::error_code ec;
				m_packet.decompress(*m_decompressor, ec);
				if (ec)
				{
					full_stop(ec);
					break;
				}
			}
			
			process_packet(m_packet);

			m_packet.clear();
			++m_in_seq_nr;
		}
	}
	
	uint32 at_least = m_iblocksize;
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

void basic_connection::process_packet(ipacket& in)
{
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
				full_stop(error::make_error_code(error::disconnect_by_host));
				break;

			case msg_kexinit:				process_kexinit(in, out, ec);				break;
			case msg_newkeys:				process_newkeys(in, out, ec);				break;

			case msg_service_accept:		process_service_accept(in, out, ec);		break;
			case msg_userauth_success:		process_userauth_success(in, out, ec);		break;
			case msg_userauth_failure:		process_userauth_failure(in, out, ec);		break;
			case msg_userauth_banner:		process_userauth_banner(in, out, ec);		break;
			case msg_userauth_info_request:	process_userauth_info_request(in, out, ec);	break;

			// channel
			case msg_channel_open:
				if (m_authenticated)
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
				if (m_authenticated)
					process_channel(in, out, ec);
				break;

			case msg_ignore:
			default:
				break;
		}
	}
	
	if (ec)
		handle_connect_result(ec);

	if (not out.empty())
	{
		async_write(move(out), [this](const boost::system::error_code& ec, size_t)
			{
				if (ec)
					full_stop(ec);
			});
	}
}

bool basic_connection::validate_host_key(const string& pk_alg, const vector<uint8>& host_key)
{
	return true;
}

void basic_connection::process_kexinit(ipacket& in, opacket& out, boost::system::error_code& ec)
{
	m_host_payload = in;
	
	string key_exchange_alg;
	in.skip(16);
	in >> key_exchange_alg;
	
	key_exchange_alg = choose_protocol(key_exchange_alg, m_alg_kex);
	
	m_key_exchange = key_exchange::create(key_exchange_alg, m_host_version, m_session_id, m_host_payload, m_my_payload);

	if (m_key_exchange)
	{
		m_key_exchange->cb_verify_host_key = boost::bind(&basic_connection::validate_host_key, this, _1, _2);
		m_key_exchange->process(in, out, ec);
	}
	else
		handle_connect_result(error::make_error_code(error::key_exchange_failed));
}

void basic_connection::process_newkeys(ipacket& in, opacket& out, boost::system::error_code& ec)
{
	ipacket payload(&m_host_payload[0], m_host_payload.size());

	string key_exchange_alg, server_host_key_alg, encryption_alg_c2s, encryption_alg_s2c,
		MAC_alg_c2s, MAC_alg_s2c, compression_alg_c2s, compression_alg_s2c;
	
	payload.skip(16);
	payload	>> key_exchange_alg
			>> server_host_key_alg
			>> encryption_alg_c2s
			>> encryption_alg_s2c
			>> MAC_alg_c2s
			>> MAC_alg_s2c
			>> compression_alg_c2s
			>> compression_alg_s2c;
	
	// Client to server encryption
	string protocol = choose_protocol(encryption_alg_c2s, m_alg_enc_c2s);
	
	const uint8* key = m_key_exchange->key(key_exchange::C);
	const uint8* iv = m_key_exchange->key(key_exchange::A);
	
	if (protocol == "3des-cbc")
		m_encryptor.reset(new CBC_Mode<DES_EDE3>::Encryption(key, 24, iv));
	else if (protocol == "blowfish-cbc")
		m_encryptor.reset(new CBC_Mode<Blowfish>::Encryption(key, 16, iv));
	else if (protocol == "aes128-cbc")
		m_encryptor.reset(new CBC_Mode<AES>::Encryption(key, 16, iv));
	else if (protocol == "aes192-cbc")
		m_encryptor.reset(new CBC_Mode<AES>::Encryption(key, 24, iv));
	else if (protocol == "aes256-cbc")
		m_encryptor.reset(new CBC_Mode<AES>::Encryption(key, 32, iv));
	else if (protocol == "aes128-ctr")
		m_encryptor.reset(new CBC_Mode<AES>::Encryption(key, 16, iv));
	else if (protocol == "aes192-ctr")
		m_encryptor.reset(new CTR_Mode<AES>::Encryption(key, 24, iv));
	else if (protocol == "aes256-ctr")
		m_encryptor.reset(new CTR_Mode<AES>::Encryption(key, 32, iv));

	// Server to client encryption
	protocol = choose_protocol(encryption_alg_s2c, m_alg_enc_s2c);

	key = m_key_exchange->key(key_exchange::D);
	iv = m_key_exchange->key(key_exchange::B);
	
	if (protocol == "3des-cbc")
		m_decryptor.reset(new CBC_Mode<DES_EDE3>::Decryption(key, 24, iv));
	else if (protocol == "blowfish-cbc")
		m_decryptor.reset(new CBC_Mode<Blowfish>::Decryption(key, 16, iv));
	else if (protocol == "aes128-cbc")
		m_decryptor.reset(new CBC_Mode<AES>::Decryption(key, 16, iv));
	else if (protocol == "aes192-cbc")
		m_decryptor.reset(new CBC_Mode<AES>::Decryption(key, 24, iv));
	else if (protocol == "aes256-cbc")
		m_decryptor.reset(new CBC_Mode<AES>::Decryption(key, 32, iv));
	else if (protocol == "aes128-ctr")
		m_decryptor.reset(new CTR_Mode<AES>::Decryption(key, 16, iv));
	else if (protocol == "aes192-ctr")
		m_decryptor.reset(new CTR_Mode<AES>::Decryption(key, 24, iv));
	else if (protocol == "aes256-ctr")
		m_decryptor.reset(new CTR_Mode<AES>::Decryption(key, 32, iv));
	
	// Client To Server verification
	protocol = choose_protocol(MAC_alg_c2s, m_alg_ver_c2s);
	iv = m_key_exchange->key(key_exchange::E);

	if (protocol == "hmac-sha1")
		m_signer.reset(new HMAC<SHA1>(iv, 20));
	else
		m_signer.reset(new HMAC<Weak::MD5>(iv));

	// Server to Client verification

	protocol = choose_protocol(MAC_alg_s2c, m_alg_ver_s2c);
	iv = m_key_exchange->key(key_exchange::F);

	if (protocol == "hmac-sha1")
		m_verifier.reset(new HMAC<SHA1>(iv, 20));
	else
		m_verifier.reset(new HMAC<Weak::MD5>(iv));
	
	// Client to Server compression
	protocol = choose_protocol(compression_alg_c2s, m_alg_cmp_c2s);
	if (not m_compressor and protocol == "zlib")
		m_compressor.reset(new compression_helper(true));
	else if (protocol == "zlib@openssh.com")
		m_delay_compressor = true;

	// Server to Client compression
	protocol = choose_protocol(compression_alg_s2c, m_alg_cmp_s2c);
	if (not m_decompressor and protocol == "zlib")
		m_decompressor.reset(new compression_helper(false));
	else if (protocol == "zlib@openssh.com")
		m_delay_decompressor = true;
	
	if (m_decryptor)
	{
		m_iblocksize = m_decryptor->OptimalBlockSize();
		m_oblocksize = m_encryptor->OptimalBlockSize();
	}
	
	if (m_authenticated)
	{
		delete m_key_exchange;
		m_key_exchange = nullptr;
	}
	else
	{
		out = msg_service_request;
		out << "ssh-userauth";
		
		// fetch the private keys
		ssh_agent& agent(ssh_agent::instance());
		for (ssh_agent::iterator pk = agent.begin(); pk != agent.end(); ++pk)
		{
			opacket blob;
			blob << *pk;
			m_private_keys.push_back(blob);
		}
	}
}

void basic_connection::process_service_accept(ipacket& in, opacket& out, boost::system::error_code& ec)
{
	out = msg_userauth_request;
	out << m_user << "ssh-connection" << "none";
}

void basic_connection::process_userauth_success(ipacket& in, opacket& out, boost::system::error_code& ec)
{
	m_authenticated = true;
	
	if (m_delay_compressor)
		m_compressor.reset(new compression_helper(true));

	if (m_delay_decompressor)
		m_decompressor.reset(new compression_helper(false));

	delete m_key_exchange;
	m_key_exchange = nullptr;
	
	handle_connect_result(boost::system::error_code());
}

void basic_connection::process_userauth_failure(ipacket& in, opacket& out, boost::system::error_code& ec)
{
	string s;
	bool partial;
	
	in >> s >> partial;
	
	if (choose_protocol(s, "publickey") == "publickey" and not m_private_keys.empty())
	{
		out = opacket(msg_userauth_request)
			<< m_user << "ssh-connection" << "publickey" << false
			<< "ssh-rsa" << m_private_keys.front();
		m_private_keys.pop_front();
		m_auth_state = auth_state_public_key;
	}
	else if (choose_protocol(s, "password") == "password" and m_request_password_cb and ++m_password_attempts <= 3)
		m_request_password_cb();
	else
		handle_connect_result(error::make_error_code(error::auth_cancelled_by_user));
}

void basic_connection::process_userauth_banner(ipacket& in, opacket& out, boost::system::error_code& ec)
{
	string msg, lang;
	in >> msg >> lang;
	
	for_each(m_channels.begin(), m_channels.end(), [msg, lang](channel* c) { c->banner(msg, lang); });
}

void basic_connection::process_userauth_info_request(ipacket& in, opacket& out, boost::system::error_code& ec)
{
	out = msg_userauth_request;

	if (m_auth_state == auth_state_public_key)
	{
		string alg;
		ipacket blob;
	
		in >> alg >> blob;
	
		out << m_user << "ssh-connection" << "publickey" << true << "ssh-rsa" << blob;
	
		opacket session_id;
		session_id << m_session_id;
		
		out << ssh_private_key(blob).sign(session_id, out);
	}
}

void basic_connection::password(const string& pw)
{
	opacket out(msg_userauth_request);
	out << m_user << "ssh-connection" << "password" << false << pw;
	async_write(move(out),
		[this](const boost::system::error_code& ec, size_t)
		{
			if (ec)
				full_stop(ec);
		}
	);
}

void basic_connection::full_stop(const boost::system::error_code& ec)
{
	disconnect();
	handle_connect_result(ec);
}

struct packet_encryptor
{
    typedef char char_type;
	struct category : io::multichar_output_filter_tag, io::flushable_tag {};

				packet_encryptor(StreamTransformation& cipher,
						MessageAuthenticationCode& signer, uint32 blocksize, uint32 seq_nr)
					: m_cipher(cipher), m_signer(signer), m_blocksize(blocksize), m_flushed(false)
				{
					for (int i = 3; i >= 0; --i)
					{
						uint8 ch = static_cast<uint8>(seq_nr >> (i * 8));
						m_signer.Update(&ch, 1);
					}
					
					m_block.reserve(m_blocksize);
				}
	
	template<typename Sink>
	streamsize	write(Sink& sink, const char* s, streamsize n)
				{
					streamsize result = 0;
					
					for (streamsize o = 0; o < n; o += m_blocksize)
					{
						streamsize k = n;
						if (k > m_blocksize - m_block.size())
							k = m_blocksize - m_block.size();
						
						const uint8* sp = reinterpret_cast<const uint8*>(s);
	
						m_signer.Update(sp, static_cast<size_t>(k));
						m_block.insert(m_block.end(), sp, sp + k);

						result += k;
						s += k;
						
						if (m_block.size() == m_blocksize)
						{
							vector<uint8> block(m_blocksize);
							m_cipher.ProcessData(&block[0], &m_block[0], m_blocksize);
							
							for (uint32 i = 0; i < m_blocksize; ++i)
								io::put(sink, block[i]);
	
							m_block.clear();
						}
					}

                    return result;
				}

	template<typename Sink>
	bool		flush(Sink& sink)
				{
					if (not m_flushed)
					{
						assert(m_block.size() == 0);

						vector<uint8> digest(m_signer.DigestSize());
						m_signer.Final(&digest[0]);
						for (size_t i = 0; i < digest.size(); ++i)
							io::put(sink, digest[i]);

						m_flushed = true;
					}

					return true;
				}

	StreamTransformation&		m_cipher;
	MessageAuthenticationCode&	m_signer;
	vector<uint8>				m_block;
	uint32						m_blocksize;
	bool						m_flushed;
};

void basic_connection::async_write_packet_int(opacket&& p, basic_write_op* op)
{
	boost::asio::streambuf* request(new boost::asio::streambuf);
	
	if (m_compressor)
	{
		boost::system::error_code ec;
		p.compress(*m_compressor, ec);
		
		if (ec)
		{
			(*op)(ec, 0);
			delete op;
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

void basic_connection::open_channel(channel* ch, uint32 channel_id)
{
	if (find(m_channels.begin(), m_channels.end(), ch) == m_channels.end())
	{
		// some sanity check first
		assert(find_if(m_channels.begin(), m_channels.end(),
			[channel_id](const channel* ch) -> bool { return ch->my_channel_id() == channel_id; } ) == m_channels.end());
		assert(not ch->is_open());

		m_channels.push_back(ch);
	}
	
	if (m_authenticated)
	{
		opacket out(msg_channel_open);
		out << "session" << channel_id << kWindowSize << kMaxPacketSize;
		async_write(move(out));
	}
}

void basic_connection::close_channel(channel* ch, uint32 channel_id)
{
	if (ch->is_open())
	{
		if (m_authenticated)
		{
			opacket out(msg_channel_close);
			out << channel_id;
			async_write(move(out));
		}

		ch->closed();
	}
	
	if (find(m_channels.begin(), m_channels.end(), ch) != m_channels.end())
	{
		m_channels.erase(
			remove(m_channels.begin(), m_channels.end(), ch),
			m_channels.end());
	}
}

void basic_connection::process_channel_open(ipacket& in, opacket& out)
{
	channel* c = nullptr;
	
	string type;

	in >> type;

	try
	{
		if (type == "x11")
			c = new x11_channel(*this);
		else if (type == "auth-agent@openssh.com" and m_forward_agent)
			c = new ssh_agent_channel(*this);
	}
	catch (...) {}
	
	if (c != nullptr)
	{
		in.message(msg_channel_open_confirmation);
		c->process(in);
		m_channels.push_back(c);
	}
	else
	{
		uint32 host_channel_id;
		in >> host_channel_id;

		const uint32 SSH_OPEN_UNKNOWN_CHANNEL_TYPE = 3;
		out = msg_channel_open_failure;
		out << host_channel_id << SSH_OPEN_UNKNOWN_CHANNEL_TYPE << "unsupported channel type" << "en";
	}
}

void basic_connection::process_channel(ipacket& in, opacket& out, boost::system::error_code& ec)
{
	try
	{
		uint32 channel_id;
		in >> channel_id;
	
		foreach (channel* c, m_channels)
		{
			if (c->my_channel_id() == channel_id)
			{
				c->process(in);
				break;
			}
		}
	}
	catch (...) {}
}

// --------------------------------------------------------------------

connection::connection(boost::asio::io_service& io_service,
		const string& user, const string& host, uint16 port)
	: basic_connection(io_service, user)
	, m_socket(io_service), m_resolver(io_service), m_host(host), m_port(port)
{
}

void connection::disconnect()
{
	basic_connection::disconnect();
	
	m_socket.close();
}

void connection::start_handshake()
{
	if (not m_socket.is_open())
	{
		boost::asio::ip::tcp::resolver resolver(get_io_service());
		boost::asio::ip::tcp::resolver::query query(m_host, boost::lexical_cast<string>(m_port));
		
		m_resolver.async_resolve(query,
			boost::bind(&connection::handle_resolve, this,
				boost::asio::placeholders::error, boost::asio::placeholders::iterator));
	}
	else
		basic_connection::start_handshake();
}

bool connection::validate_host_key(const std::string& pk_alg, const std::vector<uint8>& host_key)
{
	return m_validate_host_key_cb and m_validate_host_key_cb(m_host, pk_alg, host_key);
}

void connection::handle_resolve(const boost::system::error_code& ec, boost::asio::ip::tcp::resolver::iterator endpoint_iterator)
{
	if (ec)
		handle_connect_result(ec);
	else
	{
		boost::asio::ip::tcp::endpoint endpoint = *endpoint_iterator;
		m_socket.async_connect(endpoint,
			boost::bind(&connection::handle_connect, this,
				boost::asio::placeholders::error, ++endpoint_iterator));
	}
}

void connection::handle_connect(const boost::system::error_code& ec, boost::asio::ip::tcp::resolver::iterator endpoint_iterator)
{
	if (not ec)
		start_handshake();
	else if (endpoint_iterator != boost::asio::ip::tcp::resolver::iterator())
    {
      // The connection failed. Try the next endpoint in the list.
      m_socket.close();
      boost::asio::ip::tcp::endpoint endpoint = *endpoint_iterator;
      m_socket.async_connect(endpoint,
          boost::bind(&connection::handle_connect, this,
            boost::asio::placeholders::error, ++endpoint_iterator));
    }
    else
		handle_connect_result(ec);
}

void connection::async_write_int(boost::asio::streambuf* request, basic_write_op* op)
{
	boost::asio::async_write(m_socket, *request,
		[op, request](const boost::system::error_code& ec, size_t bytes_transferred)
		{
			delete request;
			(*op)(ec, bytes_transferred);
			delete op;
		});
}

void connection::async_read_version_string()
{
	boost::asio::async_read_until(m_socket, m_response, "\n",
		[this](const boost::system::error_code& ec, size_t bytes_transferred)
	{
		handle_protocol_version_response(ec, bytes_transferred);
	});
}

void connection::async_read(uint32 at_least)
{
	boost::asio::async_read(m_socket, m_response, boost::asio::transfer_at_least(at_least),
		[this](const boost::system::error_code& ec, size_t bytes_transferred)
		{
			this->received_data(ec);
		});
}

}

