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

#include <cryptopp/osrng.h>

#include <assh/packet.hpp>
#include <assh/error.hpp>

namespace assh
{

namespace io = boost::iostreams;
namespace ba = boost::algorithm;

//const std::vector<std::string>
//	kKeyExchangeAlgorithms = { "diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1" },
//	kServerHostKeyAlgorithms = { "ssh-rsa", "ssh-dss" },
//	kEncryptionAlgorithms = { "aes256-ctr", "aes192-ctr", "aes128-ctr", "aes256-cbc", "aes192-cbc", "aes128-cbc", "blowfish-cbc", "3des-cbc" },
//	kMacAlgorithms = { "hmac-sha1", "hmac-md5" },
//	kUseCompressionAlgorithms = { "zlib@openssh.com", "zlib", "none" },
//	kDontUseCompressionAlgorithms = { "none", "zlib@openssh.com", "zlib" };

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

const CryptoPP::Integer
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
					{
					}

					~basic_connection()
					{
					}

	template<class Handler>
	class handshake
	{
	  public:
		enum stage_type { start, request_version, received_version, sent_kexinit,
			process_kexinit };

							handshake(basic_connection& connection, Handler&& handler, stage_type stage = start)
								: m_connection(connection), m_handler(std::move(handler)), m_stage(stage)
							{
							}

							handshake(const handshake& rhs, stage_type stage)
								: m_connection(rhs.m_connection), m_handler(rhs.m_handler), m_stage(stage)
							{
							}

							handshake(const handshake& rhs)
								: m_connection(rhs.m_connection), m_handler(rhs.m_handler), m_stage(rhs.m_stage)
							{
							}

		handshake&			operator=(const handshake&);

							handshake(handshake&& rhs)
								: m_connection(std::move(rhs.m_connection))
								, m_handler(std::move(rhs.m_handler))
								, m_stage(std::move(rhs.m_stage))
							{
							}
		
		void				operator()(const boost::system::error_code& ec, std::size_t bytes_transferred)
							{
								if (ec)
									m_handler(ec);
								else
								{
									switch (m_stage)
									{
										case start:
										{
											m_connection.m_connected = true;

											const char kVersion[] = "SSH-2.0-libassh\r\n";

											boost::asio::async_write(m_connection.m_socket,
												boost::asio::const_buffers_1(kVersion, std::strlen(kVersion)),
												handshake<Handler>(*this, request_version));
											break;
										}

										case request_version:
											boost::asio::async_read_until(
												m_connection.m_socket, m_connection.m_response, "\n", handshake<Handler>(*this, received_version));
											break;
										
										case received_version:
										{
											std::istream response_stream(&m_connection.m_response);
											
											std::getline(response_stream, m_connection.m_host_version);
											ba::trim_right(m_connection.m_host_version);
											
											if (ba::starts_with(m_connection.m_host_version, "SSH-2.0"))
												m_connection.start_keyexchange(handshake<Handler>(*this, sent_kexinit));
											else
												m_handler(error::make_error_code(error::protocol_version_not_supported));
										}
										
										case sent_kexinit:
										{
											m_connection.async_read_packet(handshake<Handler>(*this, process_kexinit));
											break;
										}
										
										default:
											break;
									}
								}
							}
		
		void				operator()(boost::system::error_code ec, ipacket& in)
							{
								if (not ec)
								{
									opacket out;
									boost::system::error_code ec;
									
									switch (in.message())
									{
										case kexinit:		out = m_connection.process_kexinit(in, ec); 	break;
										case kexdh_reply:	out = m_connection.process_kexdhreply(in, ec);	break;
										default:			ec = error::protocol_error;						break;
									}

									if (not ec)
										m_connection.async_send_packet(out, handshake(*this, process_kexinit));
								}

								if (ec)
									m_handler(ec);
							}

		basic_connection&		m_connection;
		Handler					m_handler;
		stage_type				m_stage;
	};

	template<typename Handler>
	void			async_connect(const std::string& user, Handler&& handler)
					{
					    BOOST_ASIO_CONNECT_HANDLER_CHECK(ConnectHandler, handler) type_check;

						m_connected = m_authenticated = false;
						m_auth_state = auth_state_none;
						m_password_attempts = 0;
						m_in_seq_nr = m_out_seq_nr = 0;
						m_blocksize = 8;
						
						handshake<Handler>(*this, std::move(handler))(boost::system::error_code(), 0);
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

						CryptoPP::AutoSeededRandomPool	rng;
					
						if (choose_protocol(m_kex_alg, kKeyExchangeAlgorithms) == "diffie-hellman-group14-sha1")
						{
							do
							{
								m_x.Randomize(rng, 2, q14 - 1);
								m_e = CryptoPP::a_exp_b_mod_c(2, m_x, p14);
							}
							while (m_e < 1 or m_e >= p14 - 1);
						}
						else if (choose_protocol(m_kex_alg, kKeyExchangeAlgorithms) == "diffie-hellman-group1-sha1")
						{
							do
							{
								m_x.Randomize(rng, 2, q2 - 1);
								m_e = CryptoPP::a_exp_b_mod_c(2, m_x, p2);
							}
							while (m_e < 1 or m_e >= p2 - 1);
						}
						else
							ec = error::make_error_code(error::key_exchange_failed);

						opacket out(kexdh_init);
						out << m_e;
						return out;
					}

	opacket			process_kexdhreply(const ipacket& in, boost::system::error_code& ec)
					{
						ipacket hostkey, signature;
						CryptoPP::Integer f;
					
						in >> hostkey >> f >> signature;
						
//						std::string hostName = mIPAddress;
//						if (mPortNumber != 22)
//							hostName = hostName + ':' + boost::lexical_cast<string>(mPortNumber);
					
						CryptoPP::Integer K;
						if (choose_protocol(m_kex_alg, kKeyExchangeAlgorithms) == "diffie-hellman-group14-sha1")
							K = CryptoPP::a_exp_b_mod_c(f, m_x, p14);
						else
							K = CryptoPP::a_exp_b_mod_c(f, m_x, p2);
					
						opacket h_test;
						h_test << kSSHVersionString << m_host_version
							   << m_my_payload << m_host_payload
							   << hostkey
							   << m_e << f << K;
					
						std::vector<byte> H(h_test.hash());
					
						if (m_session_id.empty())
							m_session_id = H;
					
						unique_ptr<PK_Verifier> h_key;
					
						std::string pk_type;
						ipacket pk_rs;
						signature >> pk_type >> pk_rs;
					
//						if (not MKnownHosts::Instance().CheckHost(hostName, pk_type, hostkey))
//							Error(error::make_error_code(error::host_key_not_verifiable));
					
						std::string h_pk_type;
						hostkey >> h_pk_type;
					
						if (h_pk_type == "ssh-dss")
						{
							CryptoPP::Integer h_p, h_q, h_g, h_y;
							hostkey >> h_p >> h_q >> h_g >> h_y;
					
							h_key.reset(new GDSA<SHA1>::Verifier(h_p, h_q, h_g, h_y));
						}
						else if (h_pk_type == "ssh-rsa")
						{
							CryptoPP::Integer h_e, h_n;
							hostkey >> h_e >> h_n;
					
							h_key.reset(new RSASSA_PKCS1v15_SHA_Verifier(h_n, h_e));
						}
					
						if (pk_type != h_pk_type or not h_key->VerifyMessage(&H[0], dLen, pk_rs.peek(), pk_rs.size()))
							ec = error::make_error_code(error::host_key_verification_failed);
					
						int keyLen = 16;
					
						if (keyLen < 20 and choose_protocol(mMACAlgC2S, kMacAlgorithms) == "hmac-sha1")
							keyLen = 20;
					
						if (keyLen < 20 and choose_protocol(mMACAlgS2C, kMacAlgorithms) == "hmac-sha1")
							keyLen = 20;
					
						if (keyLen < 24 and choose_protocol(mEncryptionAlgC2S, kEncryptionAlgorithms) == "3des-cbc")
							keyLen = 24;
					
						if (keyLen < 24 and choose_protocol(mEncryptionAlgS2C, kEncryptionAlgorithms) == "3des-cbc")
							keyLen = 24;
					
						if (keyLen < 24 and ba::starts_with(choose_protocol(mEncryptionAlgC2S, kEncryptionAlgorithms), "aes192-"))
							keyLen = 24;
					
						if (keyLen < 24 and ba::starts_with(choose_protocol(mEncryptionAlgS2C, kEncryptionAlgorithms), "aes192-"))
							keyLen = 24;
					
						if (keyLen < 32 and ba::starts_with(choose_protocol(mEncryptionAlgC2S, kEncryptionAlgorithms), "aes256-"))
							keyLen = 32;
					
						if (keyLen < 32 and ba::starts_with(choose_protocol(mEncryptionAlgS2C, kEncryptionAlgorithms), "aes256-"))
							keyLen = 32;
					
						for (int i = 0; i < 6; ++i)
							derivekey(K, &H[0], i, keyLen, m_keys[i]);
						
						return opacket(newkeys);
					}

	template<typename Handler>
	void			start_keyexchange(Handler&& handler)
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
						
						async_send_packet(out, std::move(handler));
						
						m_my_payload = out;

						// start the read
						boost::asio::async_read(m_socket, m_response, boost::asio::transfer_at_least(8),
							boost::bind(&basic_connection::received_data, this, boost::asio::placeholders::error));
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
						m_handler(ec, bytes_transferred);
					}
		
		basic_connection&	m_connection;
		Handler				m_handler;
		streambuf_ptr		m_request;
	};

	template<typename Handler>
	void			async_send_packet(const opacket& p, Handler&& handler)
					{
						streambuf_ptr request(new boost::asio::streambuf);
						
						//io::filtering_stream<io::output> out;
						////if (m_compressor)
						////	out.push(*m_compressor);
						////if (m_encryptor_cypher)
						////	out.push(encrypt_op(m_out_seq_nr, m_encryptor_cypher, m_signer));
						//out.push(*request);
						std::ostream out(request.get());
						
						p.write(out, m_blocksize);
						
						++m_out_seq_nr;
						boost::asio::async_write(m_socket, *request, write_op<Handler>(*this, request, std::move(handler)));
					}

	void			received_data(const boost::system::error_code& ec)
					{
						if (ec)
						{
							full_stop(ec);
							return;
						}
						
						while (m_response.size() >= m_blocksize)
						{
							std::vector<char> block(m_blocksize);
							m_response.sgetn(&block[0], m_blocksize);

							//if (m_decryptor_cypher)
							//{
					  //  		std::vector<byte> data(blockSize);
					  //  		m_decryptor_cypher->ProcessData(&data[0], &b[0], blockSize);    			
				   // 			std::swap(data, block);
							//}

							m_packet.append(block);
							if (m_packet.full())
							{

//									if (mVerifier)
//									{
//										if (mResponse.size() < mVerifier->DigestSize())
//											break;
//										
//										for (int32 i = 3; i >= 0; --i)
//										{
//											byte b = mInSequenceNr >> (i * 8);
//											mVerifier->Update(&b, 1);
//										}
//										mVerifier->Update(&m_packet[0], m_packet.size());
//										
//										vector<byte> b2(mVerifier->DigestSize());
//										in.read(reinterpret_cast<char*>(&b2[0]), mVerifier->DigestSize());
//										
//										if (not mVerifier->Verify(&b2[0]))
//											Error(error::make_error_code(error::mac_error));
//									}

								if (not m_read_handlers.empty())
								{
									basic_read_handler* handler = m_read_handlers.front();
									m_read_handlers.pop_front();
									
									handler->receive_and_post(std::move(m_packet), m_socket.get_io_service());

									delete handler;
								}

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

	void			process(const ipacket& p)
					{
						
					}

	void			process_kexinit(const ipacket& p)
					{
						
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

	enum auth_state
	{
		auth_state_none,
		public_key,
		keyboard_interactive,
		password
	};

	socket_type&			m_socket;
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

	CryptoPP::Integer		m_x, m_e;
	
	std::deque<basic_read_handler*>
							m_read_handlers;
	
	std::string				m_host_version;
	boost::random::random_device
							m_rng;
};

typedef basic_connection<boost::asio::ip::tcp::socket> connection;
	
}
