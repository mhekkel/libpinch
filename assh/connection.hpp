//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include <iostream>

#include <boost/asio.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/random/random_device.hpp>
#include <boost/random/uniform_int_distribution.hpp>
#include <boost/iostreams/filtering_stream.hpp>

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

#include <assh/packet.hpp>
#include <assh/error.hpp>
#include <assh/hash.hpp>

namespace assh
{
	
using namespace CryptoPP;

namespace io = boost::iostreams;
namespace ba = boost::algorithm;

//const std::vector<std::string>
//	kKeyExchangeAlgorithms = { "diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1" },
//	kServerHostKeyAlgorithms = { "ssh-rsa", "ssh-dss" },
//	kEncryptionAlgorithms = { "aes256-ctr", "aes192-ctr", "aes128-ctr", "aes256-cbc", "aes192-cbc", "aes128-cbc", "blowfish-cbc", "3des-cbc" },
//	kMacAlgorithms = { "hmac-sha1", "hmac-md5" },
//	kUseCompressionAlgorithms = { "zlib@openssh.com", "zlib", "none" },
//	kDontUseCompressionAlgorithms = { "none", "zlib@openssh.com", "zlib" };

const std::string kSSHVersionString("SSH-2.0-libassh");

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

template<typename SOCKET>
class basic_connection
{
  public:
	typedef SOCKET									socket_type;

	typedef std::shared_ptr<boost::asio::streambuf>	streambuf_ptr;

					basic_connection(socket_type& socket)
						: m_socket(socket)
						, m_connect_handler(nullptr)
					{
					}

					~basic_connection()
					{
						delete m_connect_handler;
					}

	struct basic_connect_handler
	{
		virtual void		operator()(const boost::system::error_code& ec) = 0;
	};

	template<class Handler>
	struct connect_handler : public basic_connect_handler
	{
							connect_handler(Handler&& handler) : m_handler(std::move(handler)) {}
							connect_handler(connect_handler&& rhs) : m_handler(std::move(rhs.m_handler)) {}
							connect_handler(const connect_handler&);
		connect_handler&	operator=(const connect_handler&);
		
		virtual void		operator()(const boost::system::error_code& ec)		{ m_handler(ec); }
		
		Handler				m_handler;
	};

	template<typename Handler>
	void			async_connect(const std::string& user, Handler&& handler)
					{
					    BOOST_ASIO_CONNECT_HANDLER_CHECK(ConnectHandler, handler) type_check;
					    
					    if (m_connect_handler != nullptr)
					    	handler(error::make_error_code(error::protocol_error));
					    else
					    {
							m_authenticated = false;
							m_auth_state = auth_state_none;
							m_password_attempts = 0;
							m_in_seq_nr = m_out_seq_nr = 0;
							m_blocksize = 8;
							
							m_connect_handler = new connect_handler<Handler>(std::move(handler));
							
							static const std::string versionstring = kSSHVersionString + "\r\n";

							boost::asio::async_write(m_socket,
								boost::asio::const_buffers_1(versionstring.c_str(), versionstring.length()),
								boost::bind(&basic_connection::handle_protocol_version_request, this, boost::asio::placeholders::error));
					    }
					}

	void			handle_protocol_version_request(const boost::system::error_code& ec)
					{
						if (ec)
							(*m_connect_handler)(ec);
						else
							boost::asio::async_read_until(m_socket, m_response, "\n",
								boost::bind(&basic_connection::handle_protocol_version_response, this, boost::asio::placeholders::error));
					}

	void			handle_protocol_version_response(const boost::system::error_code& ec)
					{
						if (ec)
							(*m_connect_handler)(ec);
						else
						{
							std::istream response_stream(&m_response);
							
							std::getline(response_stream, m_host_version);
							ba::trim_right(m_host_version);
							
							if (ba::starts_with(m_host_version, "SSH-2.0"))
							{
								opacket out(kexinit);
								
								boost::random::uniform_int_distribution<uint8> rb;
								for (uint32 i = 0; i < 16; ++i)
									out << rb(m_rng);
								
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
								
								async_send_packet(out, boost::bind(&basic_connection::handle_kexinit_sent, this, boost::asio::placeholders::error));
								
								m_my_payload = out;
								
								boost::asio::async_read(m_socket, m_response, boost::asio::transfer_at_least(8),
									boost::bind(&basic_connection::received_data, this, boost::asio::placeholders::error));
							}
							else
								(*m_connect_handler)(error::make_error_code(error::protocol_version_not_supported));
						}
					}

	void			handle_kexinit_sent(const boost::system::error_code& ec)
					{
						if (ec)
							(*m_connect_handler)(ec);
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

	void			received_data(const boost::system::error_code& ec)
					{
						if (ec)
						{
							full_stop(ec);
							return;
						}
						
						while (m_response.size() >= m_blocksize)
						{
							std::vector<uint8> block(m_blocksize);
							m_response.sgetn(reinterpret_cast<char*>(&block[0]), m_blocksize);

							if (m_decryptor_cipher)
							{
								std::vector<uint8> data(m_blocksize);
								m_decryptor->ProcessData(&data[0], &block[0], m_blocksize);    			
								std::swap(data, block);
							}

							m_packet.append(block);

							if (m_packet.full())
							{
								m_packet.strip_padding();

//									if (mVerifier)
//									{
//										if (mResponse.size() < mVerifier->DigestSize())
//											break;
//										
//										for (int32 i = 3; i >= 0; --i)
//										{
//											uint8 b = mInSequenceNr >> (i * 8);
//											mVerifier->Update(&b, 1);
//										}
//										mVerifier->Update(&m_packet[0], m_packet.size());
//										
//										vector<uint8> b2(mVerifier->DigestSize());
//										in.read(reinterpret_cast<char*>(&b2[0]), mVerifier->DigestSize());
//										
//										if (not mVerifier->Verify(&b2[0]))
//											Error(error::make_error_code(error::mac_error));
//									}
								
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
							boost::bind(&basic_connection::received_data, this, boost::asio::placeholders::error));
					}

	void			process_packet(ipacket& in)
					{
						opacket out;
						boost::system::error_code ec;
						
						switch ((message_type)m_packet)
						{
							case kexinit:		out = process_kexinit(in, ec); 	break;
							case kexdh_reply:	out = process_kexdhreply(in, ec); break;
							case newkeys:		out = process_newkeys(in, ec);	break;
							default:
								if (not m_read_handlers.empty())
								{
									basic_read_handler* handler = m_read_handlers.front();
									m_read_handlers.pop_front();
									
									handler->receive_and_post(std::move(m_packet), m_socket.get_io_service());

									delete handler;
								}
								break;
						}
						
						if (ec and m_connect_handler)
							(*m_connect_handler)(ec);
						
						if (not out.empty())
							async_send_packet(out, [this](const boost::system::error_code& ec)
								{
									if (ec and m_connect_handler)
										(*m_connect_handler)(ec);
								});
					}

	opacket			process_kexinit(ipacket& in, boost::system::error_code& ec)
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

						AutoSeededRandomPool	rng;
					
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

	opacket			process_kexdhreply(ipacket& in, boost::system::error_code& ec)
					{
						ipacket hostkey, signature;
						Integer f;
					
						in >> hostkey >> f >> signature;
						
//						std::string hostName = mIPAddress;
//						if (mPortNumber != 22)
//							hostName = hostName + ':' + boost::lexical_cast<string>(mPortNumber);
					
						Integer K;
						if (choose_protocol(m_kex_alg, kKeyExchangeAlgorithms) == "diffie-hellman-group14-sha1")
							K = a_exp_b_mod_c(f, m_x, p14);
						else
							K = a_exp_b_mod_c(f, m_x, p2);
					
						opacket hp;
						hp << kSSHVersionString << m_host_version << m_my_payload << m_host_payload << hostkey << m_e << f << K;
						std::vector<uint8> H = hash<SHA1>().update(hp).final();
					
						if (m_session_id.empty())
							m_session_id = H;
					
						std::unique_ptr<PK_Verifier> h_key;
					
						std::string pk_type;
						ipacket pk_rs;
						signature >> pk_type >> pk_rs;
					
//						if (not MKnownHosts::Instance().CheckHost(hostName, pk_type, hostkey))
//							Error(error::make_error_code(error::host_key_not_verifiable));
					
						std::string h_pk_type;
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
					
						const std::vector<uint8>& pk_rs_d(pk_rs);
						if (pk_type != h_pk_type or not h_key->VerifyMessage(&H[0], H.size(), &pk_rs_d[0], pk_rs_d.size()))
							ec = error::make_error_code(error::host_key_verification_failed);
					
						// derive the keys, 32 bytes should be enough
						int keylen = 32;
						for (int i = 0; i < 6; ++i)
						{
							std::vector<uint8> key = (hash<SHA1>() | K | H | ('A' + i) | m_session_id).final();
							
							for (int k = 20; k < keylen; k += 20)
							{
								std::vector<uint8> k2 = (hash<SHA1>() | K | H | key).final();
								key.insert(key.end(), k2.begin(), k2.end());
							}
							
							m_keys[i].assign(key.begin(), key.begin() + keylen);
						}

						return opacket(newkeys);
					}
		
	opacket			process_newkeys(ipacket& in, boost::system::error_code& ec)
					{
						std::string protocol;
						
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
						}
						
						return out;
					}

	std::string		choose_protocol(const std::vector<std::string>& server, const std::vector<std::string>& client)
					{
						std::vector<std::string>::iterator c, s;
						
						bool found = false;
						
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

	std::string		choose_protocol(const std::vector<std::string>& server, const char* client[])
					{
						std::vector<std::string>::const_iterator s;
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


	void			full_stop(const boost::system::error_code& ec)
					{
						m_socket.close();
					}

	template<class Handler>
	struct bound_handler
	{
		bound_handler(Handler handler, const boost::system::error_code& ec, ipacket&& packet)
			: m_handler(handler), m_ec(ec), m_packet(std::move(packet)) {}

		bound_handler(bound_handler&& rhs)
			: m_handler(std::move(rhs.m_handler)), m_ec(rhs.m_ec), m_packet(std::move(rhs.m_packet)) {}

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
			: m_handler(std::move(handler)) {}
		
		virtual void receive_and_post(ipacket&& p, boost::asio::io_service& io_service)
		{
			io_service.post(bound_handler<Handler>(m_handler, boost::system::error_code(), std::move(p)));
		}

		Handler		m_handler;
	};

	template<typename Handler>
	void			async_read_packet(Handler&& handler)
					{
						typedef read_handler<Handler> handler_type;
						
						if (not m_connected)
							m_socket.get_io_service().post(bound_handler<Handler>(handler, error::connection_lost, ipacket()));
						else
							m_read_handlers.push_back(new handler_type(std::move(handler)));
					}

	template<typename Handler>
	struct write_op
	{
					write_op(basic_connection& connection, Handler&& hander)
						: m_connection(connection), m_handler(std::move(hander)) {}
					
					write_op(basic_connection& connection, streambuf_ptr request, Handler&& hander)
						: m_connection(connection), m_handler(std::move(hander)), m_request(request) {}
					
					write_op(const write_op& rhs)
						: m_connection(rhs.m_connection), m_handler(rhs.m_handler), m_request(rhs.m_request) {}
					
					write_op(write_op&& rhs)
						: m_connection(std::move(rhs.m_connection))
						, m_handler(std::move(rhs.m_handler))
						, m_request(std::move(rhs.m_request)) {}
					
		write_op&	operator=(const write_op& rhs);	

		void		operator()(const boost::system::error_code& ec)
					{
						m_handler(ec);
					}

		void		operator()(const boost::system::error_code& ec, std::size_t bytes_transferred)
					{
						m_handler(ec);
					}
		
		basic_connection&	m_connection;
		Handler				m_handler;
		streambuf_ptr		m_request;
	};

	template<typename Handler>
	void			async_send_packet(const opacket& p, Handler&& handler)
					{
						streambuf_ptr request(new boost::asio::streambuf);
						std::ostream out(request.get());
						
//						io::filtering_stream<io::output> out;
						////if (m_compressor)
						////	out.push(*m_compressor);
						////if (m_encryptor_cipher)
						////	out.push(encrypt_op(m_out_seq_nr, m_encryptor_cipher, m_signer));
//						out.push(std::ostream(request.get()));
						
						p.write(out, m_blocksize);
						
						++m_out_seq_nr;
						boost::asio::async_write(m_socket, *request, write_op<Handler>(*this, request, std::move(handler)));
					}



	enum auth_state
	{
		auth_state_none,
		public_key,
		keyboard_interactive,
		password
	};

	socket_type&			m_socket;
	basic_connect_handler*	m_connect_handler;
	bool					m_connected;
	bool					m_authenticated;
	std::vector<uint8>		m_my_payload, m_host_payload, m_session_id;
	auth_state				m_auth_state;
	uint32					m_password_attempts;
	uint32					m_in_seq_nr, m_out_seq_nr;
	ipacket					m_packet;
	uint32					m_blocksize;
	boost::asio::streambuf	m_response;
	
	std::vector<std::string>
							m_kex_alg, m_server_host_key_alg,
							m_encryption_alg_c2s, m_encryption_alg_s2c,
							m_MAC_alg_c2s, m_MAC_alg_s2c,
							m_compression_alg_c2s, m_compression_alg_s2c,
							m_lang_c2s, m_lang_s2c;

	std::unique_ptr<BlockCipher>					m_decryptor_cipher;
	std::unique_ptr<StreamTransformation>			m_decryptor;
	std::unique_ptr<BlockCipher>					m_encryptor_cipher;
	std::unique_ptr<StreamTransformation>			m_encryptor;
	std::unique_ptr<MessageAuthenticationCode>		m_signer;
	std::unique_ptr<MessageAuthenticationCode>		m_verifier;
	//std::unique_ptr<MSshPacketCompressor>					m_compressor;
	//std::unique_ptr<MSshPacketDecompressor>					m_decompressor;

	Integer		m_x, m_e;
	std::vector<uint8>		m_keys[6];
	
	std::deque<basic_read_handler*>
							m_read_handlers;
	
	std::string				m_host_version;
	boost::random::random_device
							m_rng;
};

typedef basic_connection<boost::asio::ip::tcp::socket> connection;
	
}
