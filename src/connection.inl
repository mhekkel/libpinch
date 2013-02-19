//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <assh/config.hpp>

#include <iostream>

#include <boost/asio.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/iostreams/filtering_stream.hpp>
#include <boost/iostreams/flush.hpp>

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
#include <assh/ssh_agent.hpp>

using namespace std;
using namespace CryptoPP;

namespace io = boost::iostreams;
namespace ba = boost::algorithm;

namespace assh
{

// --------------------------------------------------------------------

AutoSeededRandomPool	rng;

//const vector<string>
//	kKeyExchangeAlgorithms = { "diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1" },
//	kServerHostKeyAlgorithms = { "ssh-rsa", "ssh-dss" },
//	kEncryptionAlgorithms = { "aes256-ctr", "aes192-ctr", "aes128-ctr", "aes256-cbc", "aes192-cbc", "aes128-cbc", "blowfish-cbc", "3des-cbc" },
//	kMacAlgorithms = { "hmac-sha1", "hmac-md5" },
//	kUseCompressionAlgorithms = { "zlib@openssh.com", "zlib", "none" },
//	kDontUseCompressionAlgorithms = { "none", "zlib@openssh.com", "zlib" };

const string kSSHVersionString("SSH-2.0-libassh");

const char* kKeyExchangeAlgorithms[] = { "diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1", nullptr };
const char* kServerHostKeyAlgorithms[] = { "ssh-rsa", "ssh-dss", nullptr };
const char* kEncryptionAlgorithms[] = { "aes256-ctr", "aes192-ctr", "aes128-ctr", "aes256-cbc", "aes192-cbc", "aes128-cbc", "blowfish-cbc", "3des-cbc", nullptr };
const char* kMacAlgorithms[] = { "hmac-sha1", "hmac-md5", nullptr };
const char* kUseCompressionAlgorithms[] = { "zlib@openssh.com", "zlib", "none", nullptr };
const char* kDontUseCompressionAlgorithms[] = { "none", "zlib@openssh.com", "zlib", nullptr };

const byte
	k_p_2[] = {
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
		0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
		0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
		0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
		0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
		0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
		0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
		0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	},
	k_p_14[] = {
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
		0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
		0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
		0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
		0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
		0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
		0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
		0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D, 0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
		0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
		0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
		0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D, 0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
		0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
		0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
		0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9, 0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
		0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
		0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	};

const Integer
	p2(k_p_2, sizeof(k_p_2)),		q2((p2 - 1) / 2),
	p14(k_p_14, sizeof(k_p_14)),	q14((p14 - 1) / 2);

string choose_protocol(const vector<string>& server, const vector<string>& client);
string choose_protocol(const vector<string>& server, const char* client[]);
string choose_protocol(const vector<string>& server, const char* client);

// --------------------------------------------------------------------

template<typename SOCKET>
basic_connection<SOCKET>::basic_connection(socket_type& socket, const string& user)
	: m_socket(socket)
	, m_io_service(socket.get_io_service())
	, m_user(user)
	, m_connect_handler(nullptr)
{
}

template<typename SOCKET>
basic_connection<SOCKET>::~basic_connection()
{
	delete m_connect_handler;
}

template<typename SOCKET>
void basic_connection<SOCKET>::start_handshake(basic_connect_handler* handler)
{
    if (m_connect_handler != nullptr)
    {
    	handler->handle_connect(error::make_error_code(error::protocol_error), m_io_service);
    }
    else
	{
		m_connect_handler = handler;
	
		m_authenticated = false;
		m_auth_state = auth_state_none;
		m_password_attempts = 0;
		m_in_seq_nr = m_out_seq_nr = 0;
		m_blocksize = 8;
		
		streambuf_ptr request(new boost::asio::streambuf);
		ostream out(request.get());
		out << kSSHVersionString << "\r\n";
	
		boost::asio::async_write(m_socket, *request,
			boost::bind(&basic_connection::handle_protocol_version_request, this, boost::asio::placeholders::error, request));
	}
}

template<typename SOCKET>
void basic_connection<SOCKET>::handle_protocol_version_request(const boost::system::error_code& ec, streambuf_ptr request)
{
	if (ec)
		m_connect_handler->handle_connect(ec, m_io_service);
	else
		boost::asio::async_read_until(m_socket, m_response, "\n",
			boost::bind(&basic_connection<SOCKET>::handle_protocol_version_response, this, boost::asio::placeholders::error));
}

template<typename SOCKET>
void basic_connection<SOCKET>::handle_protocol_version_response(const boost::system::error_code& ec)
{
	if (ec)
		m_connect_handler->handle_connect(ec, m_io_service);
	else
	{
		istream response_stream(&m_response);
		
		getline(response_stream, m_host_version);
		ba::trim_right(m_host_version);
		
		if (ba::starts_with(m_host_version, "SSH-2.0"))
		{
			opacket out(kexinit);
			
			for (uint32 i = 0; i < 16; ++i)
				out << rng.GenerateByte();
			
			string compress = "none";	// "zlib@openssh.com,zlib,none"

			out << kKeyExchangeAlgorithms
				<< kServerHostKeyAlgorithms
				<< kEncryptionAlgorithms
				<< kEncryptionAlgorithms
				<< kMacAlgorithms
				<< kMacAlgorithms
				<< compress
				<< compress
				<< ""
				<< ""
				<< false
				<< uint32(0);
			
			async_send_packet(out, [this](const boost::system::error_code& ec)
			{
				if (ec)
					m_connect_handler->handle_connect(ec, m_io_service);
			});
			
			m_my_payload = out;
			
			// start read loop
			received_data(boost::system::error_code());
		}
		else
			m_connect_handler->handle_connect(error::make_error_code(error::protocol_version_not_supported), m_io_service);
	}
}

//	template<typename Handler>
//	struct read_op
//	{
//
//
//		void		operator()(const boost::system::error_code& ec)
//					{
//						if (ec)
//							m_handler(ec);
//						else
//						{
//							
//						}
//					}
//
//		Handler		m_handler;
//	};

// the read loop, this routine keeps calling itself until an error condition is met
template<typename SOCKET>
void basic_connection<SOCKET>::received_data(const boost::system::error_code& ec)
{
	if (ec)
	{
		full_stop(ec);
		return;
	}
	
	while (m_response.size() >= m_blocksize)
	{
		if (not m_packet.full())
		{
			vector<uint8> block(m_blocksize);
			m_response.sgetn(reinterpret_cast<char*>(&block[0]), m_blocksize);

			if (m_decryptor_cipher)
			{
				vector<uint8> data(m_blocksize);
				m_decryptor->ProcessData(&data[0], &block[0], m_blocksize);
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

		if (m_packet.full())
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
			
			m_packet.strip_padding();

			process_packet(m_packet);

			m_packet.clear();
			++m_in_seq_nr;
		}
	}
	
	uint32 at_least = m_blocksize;
	if (m_response.size() >= m_blocksize)
	{
		// if we arrive here, we might have read a block, but not the digest?
		// call readsome with 0 as at-least, that will return something we hope.
		at_least = 1;
	}
	else
		at_least -= m_response.size();

	boost::asio::async_read(m_socket, m_response, boost::asio::transfer_at_least(at_least),
		[this](const boost::system::error_code& ec, size_t bytes_transferred)
		{
			this->received_data(ec);
		});
}

template<typename SOCKET>
void basic_connection<SOCKET>::process_packet(ipacket& in)
{
	opacket out;
	boost::system::error_code ec;
	
	switch ((message_type)m_packet)
	{
		case disconnect:
			if (m_connect_handler)
				m_connect_handler->handle_connect(error::make_error_code(error::connection_lost), m_io_service);
			m_socket.close();
			break;
		case kexinit:			out = process_kexinit(in, ec); 	break;
		case kexdh_reply:		out = process_kexdhreply(in, ec); break;
		case newkeys:			out = process_newkeys(in, ec);	break;
		case service_accept:	out = process_service_accept(in, ec); break;
		case userauth_success:	out = process_userauth_success(in, ec); break;
		case userauth_failure:	out = process_userauth_failure(in, ec); break;
		case userauth_banner:	out = process_userauth_banner(in, ec); break;
		case userauth_info_request:
								out = process_userauth_info_request(in, ec); break;
		case ignore:			break;
		default:
			if (m_authenticated and not m_read_handlers.empty())
			{
				basic_read_handler* handler = m_read_handlers.front();
				m_read_handlers.pop_front();
				
				handler->receive_and_post(move(m_packet), m_socket.get_io_service());

				delete handler;
			}
			break;
	}
	
	if (ec and m_connect_handler)
		m_connect_handler->handle_connect(ec, m_io_service);
	else if (not out.empty())
	{
		async_send_packet(out, [this](const boost::system::error_code& ec)
			{
				if (ec and m_connect_handler)
					m_connect_handler->handle_connect(ec, m_io_service);
			});
	}
}

template<typename SOCKET>
opacket basic_connection<SOCKET>::process_kexinit(ipacket& in, boost::system::error_code& ec)
{
	// capture the packet contents for the host payload
	m_host_payload = in;

	bool first_kex_packet_follows;
	in.skip(16);
		
	in	>> m_kex_alg
		>> m_server_host_key_alg
		>> m_encryption_alg_c2s
		>> m_encryption_alg_s2c
		>> m_MAC_alg_c2s
		>> m_MAC_alg_s2c
		>> m_compression_alg_c2s
		>> m_compression_alg_s2c
		>> m_lang_c2s
		>> m_lang_s2c
		>> first_kex_packet_follows;

	m_e = 0;

	if (choose_protocol(m_kex_alg, kKeyExchangeAlgorithms) == "diffie-hellman-group14-sha1")
	{
		do
		{
			m_x.Randomize(rng, 2, q14 - 1);
			m_e = a_exp_b_mod_c(2, m_x, p14);
		}
		while (m_e < 1 or m_e >= p14 - 1);
	}
	else if (choose_protocol(m_kex_alg, kKeyExchangeAlgorithms) == "diffie-hellman-group1-sha1")
	{
		do
		{
			m_x.Randomize(rng, 2, q2 - 1);
			m_e = a_exp_b_mod_c(2, m_x, p2);
		}
		while (m_e < 1 or m_e >= p2 - 1);
	}
	else
		ec = error::make_error_code(error::key_exchange_failed);

	opacket out(kexdh_init);
	out << m_e;
	return out;
}

template<typename SOCKET>
opacket basic_connection<SOCKET>::process_kexdhreply(ipacket& in, boost::system::error_code& ec)
{
	ipacket hostkey, signature;
	Integer f;

	in >> hostkey >> f >> signature;
	
//						string hostName = mIPAddress;
//						if (mPortNumber != 22)
//							hostName = hostName + ':' + boost::lexical_cast<string>(mPortNumber);

	Integer K;
	if (choose_protocol(m_kex_alg, kKeyExchangeAlgorithms) == "diffie-hellman-group14-sha1")
		K = a_exp_b_mod_c(f, m_x, p14);
	else
		K = a_exp_b_mod_c(f, m_x, p2);

	opacket hp;
	hp << kSSHVersionString << m_host_version << m_my_payload << m_host_payload << hostkey << m_e << f << K;
	vector<uint8> H = hash<SHA1>().update(hp).final();

	if (m_session_id.empty())
		m_session_id = H;

	unique_ptr<PK_Verifier> h_key;

	string pk_type;
	ipacket pk_rs;
	signature >> pk_type >> pk_rs;

//						if (not MKnownHosts::Instance().CheckHost(hostName, pk_type, hostkey))
//							Error(error::make_error_code(error::host_key_not_verifiable));

	string h_pk_type;
	hostkey >> h_pk_type;

	if (h_pk_type == "ssh-dss")
	{
		Integer h_p, h_q, h_g, h_y;
		hostkey >> h_p >> h_q >> h_g >> h_y;

		h_key.reset(new GDSA<SHA1>::Verifier(h_p, h_q, h_g, h_y));
	}
	else if (h_pk_type == "ssh-rsa")
	{
		Integer h_e, h_n;
		hostkey >> h_e >> h_n;

		h_key.reset(new RSASSA_PKCS1v15_SHA_Verifier(h_n, h_e));
	}

	const vector<uint8>& pk_rs_d(pk_rs);
	if (pk_type != h_pk_type or not h_key->VerifyMessage(&H[0], H.size(), &pk_rs_d[0], pk_rs_d.size()))
		ec = error::make_error_code(error::host_key_verification_failed);

	// derive the keys, 32 bytes should be enough
	int keylen = 32;
	for (int i = 0; i < 6; ++i)
	{
		vector<uint8> key = (hash<SHA1>() | K | H | ('A' + i) | m_session_id).final();
		
		for (int k = 20; k < keylen; k += 20)
		{
			vector<uint8> k2 = (hash<SHA1>() | K | H | key).final();
			key.insert(key.end(), k2.begin(), k2.end());
		}
		
		m_keys[i].assign(key.begin(), key.begin() + keylen);
	}

	return opacket(newkeys);
}

template<typename SOCKET>
opacket basic_connection<SOCKET>::process_newkeys(ipacket& in, boost::system::error_code& ec)
{
	string protocol;
	
	do
	{
		// Client to server encryption
		protocol = choose_protocol(m_encryption_alg_c2s, kEncryptionAlgorithms);
		
		if (protocol == "3des-cbc")
			m_encryptor_cipher.reset(new DES_EDE3::Encryption(&m_keys[2][0]));
		else if (protocol == "blowfish-cbc")
			m_encryptor_cipher.reset(new BlowfishEncryption(&m_keys[2][0]));
		else if (protocol == "aes128-cbc" or protocol == "aes128-ctr")
			m_encryptor_cipher.reset(new AESEncryption(&m_keys[2][0], 16));
		else if (protocol == "aes192-cbc" or protocol == "aes192-ctr")
			m_encryptor_cipher.reset(new AESEncryption(&m_keys[2][0], 24));
		else if (protocol == "aes256-cbc" or protocol == "aes256-ctr")
			m_encryptor_cipher.reset(new AESEncryption(&m_keys[2][0], 32));
		else
			break;
	
		if (ba::ends_with(protocol, "-cbc"))
			m_encryptor.reset(
				new CBC_Mode_ExternalCipher::Encryption(
					*m_encryptor_cipher.get(), &m_keys[0][0]));
		else
			m_encryptor.reset(
				new CTR_Mode_ExternalCipher::Encryption(
					*m_encryptor_cipher.get(), &m_keys[0][0]));
	
		// Server to client encryption
		protocol = choose_protocol(m_encryption_alg_s2c, kEncryptionAlgorithms);
		
		if (ba::ends_with(protocol, "-ctr"))
		{
			if (protocol == "aes128-ctr")
				m_decryptor_cipher.reset(new AESEncryption(&m_keys[3][0], 16));
			else if (protocol == "aes192-ctr")
				m_decryptor_cipher.reset(new AESEncryption(&m_keys[3][0], 24));
			else if (protocol == "aes256-ctr")
				m_decryptor_cipher.reset(new AESEncryption(&m_keys[3][0], 32));
			else
				break;
			
			m_decryptor.reset(
				new CTR_Mode_ExternalCipher::Decryption(
					*m_decryptor_cipher.get(), &m_keys[1][0]));
		}
		else
		{
			if (protocol == "3des-cbc")
				m_decryptor_cipher.reset(new DES_EDE3_Decryption(&m_keys[3][0]));
			else if (protocol == "blowfish-cbc")
				m_decryptor_cipher.reset(new BlowfishDecryption(&m_keys[3][0]));
			else if (protocol == "aes128-cbc" or protocol == "aes128-ctr")
				m_decryptor_cipher.reset(new AESDecryption(&m_keys[3][0], 16));
			else if (protocol == "aes192-cbc" or protocol == "aes192-ctr")
				m_decryptor_cipher.reset(new AESDecryption(&m_keys[3][0], 24));
			else if (protocol == "aes256-cbc" or protocol == "aes256-ctr")
				m_decryptor_cipher.reset(new AESDecryption(&m_keys[3][0], 32));
			else
				break;
		
			m_decryptor.reset(
				new CBC_Mode_ExternalCipher::Decryption(
					*m_decryptor_cipher.get(), &m_keys[1][0]));
		}
	
		protocol = choose_protocol(m_MAC_alg_c2s, kMacAlgorithms);
		if (protocol == "hmac-sha1")
			m_signer.reset(
				new HMAC<SHA1>(&m_keys[4][0], 20));
		else
			m_signer.reset(
				new HMAC<Weak::MD5>(&m_keys[4][0]));
	
		protocol = choose_protocol(m_MAC_alg_s2c, kMacAlgorithms);
		if (protocol == "hmac-sha1")
			m_verifier.reset(
				new HMAC<SHA1>(&m_keys[5][0], 20));
		else
			m_verifier.reset(
				new HMAC<Weak::MD5>(&m_keys[5][0]));
	
//							string compress;
//							if (Preferences::GetInteger("compress-sftp", true))
//								compress = kUseCompressionAlgorithms;
//							else
//								compress = kDontUseCompressionAlgorithms;
//						
//							if (choose_protocol(mCompressionAlgS2C, compress) == "zlib")
//								mCompressor.reset(new MSshPacketCompressor);
//							else
//								mDelayedCompress = choose_protocol(mCompressionAlgS2C, compress) == "zlib@openssh.com";
//						
//							if (choose_protocol(mCompressionAlgC2S, compress) == "zlib")
//								mDecompressor.reset(new MSshPacketDecompressor);
//							else
//								mDelayedDecompress = choose_protocol(mCompressionAlgC2S, compress) == "zlib@openssh.com";
	}
	while (false);
	
	if (m_decryptor)
		m_blocksize = m_decryptor_cipher->BlockSize();
	
	opacket out(undefined);
	
	if (not m_authenticated)
	{
		out = opacket(service_request);
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
	
	return out;
}

template<typename SOCKET>
opacket basic_connection<SOCKET>::process_service_accept(ipacket& in, boost::system::error_code& ec)
{
	opacket out(userauth_request);
	out << m_user << "ssh-connection" << "none";
	return out;
}

template<typename SOCKET>
opacket basic_connection<SOCKET>::process_userauth_success(ipacket& in, boost::system::error_code& ec)
{
	m_authenticated = true;
	m_connect_handler->handle_connect(boost::system::error_code(), m_io_service);

	delete m_connect_handler;
	m_connect_handler = nullptr;

	return opacket();
}

template<typename SOCKET>
opacket basic_connection<SOCKET>::process_userauth_failure(ipacket& in, boost::system::error_code& ec)
{
	vector<string> s;
	bool partial;
	opacket out;
	
	in >> s >> partial;
	
	if (choose_protocol(s, "publickey") == "publickey" and not m_private_keys.empty())
	{
		out = opacket(userauth_request)
			<< m_user << "ssh-connection" << "publickey" << false
			<< "ssh-rsa" << m_private_keys.front();
		m_private_keys.pop_front();
		m_auth_state = auth_state_public_key;
	}
	else if (choose_protocol(s, "password") == "password")
	{
//		out << 
	}
	else
		out = opacket(disconnect);

	return out;
}

template<typename SOCKET>
opacket basic_connection<SOCKET>::process_userauth_banner(ipacket& in, boost::system::error_code& ec)
{
	m_connect_handler->handle_connect(error::make_error_code(error::auth_cancelled_by_user), m_io_service);
	return opacket();
}

template<typename SOCKET>
opacket basic_connection<SOCKET>::process_userauth_info_request(ipacket& in, boost::system::error_code& ec)
{
	opacket out(userauth_request);

	if (m_auth_state == auth_state_public_key)
	{
		string alg;
		ipacket blob;
	
		in >> alg >> blob;
	
		out << m_user << "ssh-connection" << "publickey" << true << "ssh-rsa" << blob;
	
		opacket session_id;
		session_id << m_session_id;

		opacket signature;
		signature << "ssh-rsa" << ssh_private_key(blob).sign(session_id, out);

		out << signature;
	}

	return out;
}

template<typename SOCKET>
void basic_connection<SOCKET>::full_stop(const boost::system::error_code& ec)
{
	if (m_connect_handler)
		m_connect_handler->handle_connect(ec, m_io_service);

	m_socket.close();
}

template<class Handler>
struct bound_handler
{
bound_handler(Handler handler, const boost::system::error_code& ec, ipacket&& packet)
: m_handler(handler), m_ec(ec), m_packet(move(packet)) {}

bound_handler(bound_handler&& rhs)
: m_handler(move(rhs.m_handler)), m_ec(rhs.m_ec), m_packet(move(rhs.m_packet)) {}

virtual void operator()()		{ m_handler(m_ec, m_packet); }

Handler							m_handler;
const boost::system::error_code	m_ec;
ipacket							m_packet;
};

struct basic_read_handler
{
virtual void receive_and_post(ipacket&& p, boost::asio::io_service& io_service) = 0;
};

template<typename Handler>
struct read_handler : public basic_read_handler
{
read_handler(Handler&& handler)
: m_handler(move(handler)) {}

virtual void receive_and_post(ipacket&& p, boost::asio::io_service& io_service)
{
io_service.post(bound_handler<Handler>(m_handler, boost::system::error_code(), move(p)));
}

Handler		m_handler;
};

//template<typename Handler>
//struct write_op
//{
//write_op(basic_connection& connection, Handler&& hander)
//	: m_connection(connection), m_handler(move(hander)) {}
//
//write_op(basic_connection& connection, streambuf_ptr request, Handler&& hander)
//	: m_connection(connection), m_handler(move(hander)), m_request(request) {}
//
//write_op(const write_op& rhs)
//	: m_connection(rhs.m_connection), m_handler(rhs.m_handler), m_request(rhs.m_request) {}
//
//write_op(write_op&& rhs)
//	: m_connection(move(rhs.m_connection))
//	, m_handler(move(rhs.m_handler))
//	, m_request(move(rhs.m_request)) {}
//
//write_op&	operator=(const write_op& rhs);	
//
//void		operator()(const boost::system::error_code& ec)
//{
//	m_handler(ec);
//}
//
//void		operator()(const boost::system::error_code& ec, size_t bytes_transferred)
//{
//	m_handler(ec);
//}
//
//basic_connection&	m_connection;
//Handler				m_handler;
//streambuf_ptr		m_request;
//};

struct packet_encryptor
{
        typedef char							char_type;
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

template<typename SOCKET>
void basic_connection<SOCKET>::async_send_packet_int(const opacket& p, basic_write_op* op)
{
	streambuf_ptr request(new boost::asio::streambuf);

	{
		io::filtering_stream<io::output> out;
	
		if (m_encryptor)
			out.push(packet_encryptor(*m_encryptor, *m_signer, m_encryptor_cipher->BlockSize(), m_out_seq_nr));
		out.push(*request);

		p.write(out, m_blocksize);
	}

	++m_out_seq_nr;
	boost::asio::async_write(m_socket, *request, [op, request](const boost::system::error_code& ec, size_t bytes_transferred)
	{
		(void)request.get();
		
		(*op)(ec, bytes_transferred);
		delete op;
	});
}

// --------------------------------------------------------------------

string choose_protocol(const vector<string>& server, const vector<string>& client)
{
	vector<string>::const_iterator c, s;
	
	bool found = false;
	string result;
	
	for (c = client.begin(); c != client.end() and not found; ++c)
	{
		for (s = server.begin(); s != server.end() and not found; ++s)
		{
			if (*s == *c)
			{
				result = *c;
				found = true;
			}
		}
	}
	
	return result;
}

string choose_protocol(const vector<string>& server, const char* client[])
{
	vector<string>::const_iterator s;
	const char** c = client;
	
	bool found = false;
	string result;
	
	for (; *c != nullptr; ++c)
	{
		for (s = server.begin(); s != server.end() and not found; ++s)
		{
			if (*s == *c)
			{
				result = *s;
				found = true;
			}
		}
	}
	
	return result;
}

string choose_protocol(const vector<string>& server, const char* client)
{
	vector<string>::const_iterator s;
	
	bool found = false;
	string result;
	
	for (s = server.begin(); s != server.end() and not found; ++s)
	{
		if (*s == client)
		{
			result = *s;
			found = true;
		}
	}
	
	return result;
}

}

