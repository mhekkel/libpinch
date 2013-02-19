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
#include <boost/algorithm/string/find_iterator.hpp>

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
#include <assh/hash.hpp>
#include <assh/ssh_agent.hpp>

using namespace std;
using namespace CryptoPP;

namespace io = boost::iostreams;
namespace ba = boost::algorithm;

namespace assh
{

// --------------------------------------------------------------------

AutoSeededRandomPool	rng;

const string
	kSSHVersionString("SSH-2.0-libassh"),
	kKeyExchangeAlgorithms("diffie-hellman-group14-sha1,diffie-hellman-group1-sha1"),
	kServerHostKeyAlgorithms("ssh-rsa,ssh-dss"),
	kEncryptionAlgorithms("aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc,blowfish-cbc,3des-cbc"),
	kMacAlgorithms("hmac-sha1,hmac-md5"),
	kUseCompressionAlgorithms("zlib@openssh.com,zlib,none"),
	kDontUseCompressionAlgorithms("none,zlib@openssh.com,zlib");

string choose_protocol(const string& server, const string& client)
{
	string result;
	bool found = false;

	typedef ba::split_iterator<string::const_iterator> split_iter_type;
	split_iter_type c = ba::make_split_iterator(client, ba::first_finder(",", ba::is_equal()));
	split_iter_type s = ba::make_split_iterator(server, ba::first_finder(",", ba::is_equal()));
	
	for (; not found and c != split_iter_type(); ++c)
	{
		for (; not found and s != split_iter_type(); ++s)
		{
			if (*c == *s)
			{
				result = boost::copy_range<string>(*c);
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
	, m_connect_handler(nullptr)
	, m_key_exchange(nullptr)
{
}

basic_connection::~basic_connection()
{
	delete m_connect_handler;
	delete m_key_exchange;
}

void basic_connection::start_handshake(basic_connect_handler* handler)
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
		m_connect_handler->handle_connect(ec, m_io_service);
	else
		async_read_version_string();
}

void basic_connection::handle_protocol_version_response(const boost::system::error_code& ec, size_t)
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
			
			async_write(out, [this](const boost::system::error_code& ec, size_t bytes_transferred)
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

// the read loop, this routine keeps calling itself until an error condition is met
void basic_connection::received_data(const boost::system::error_code& ec)
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

	async_read(at_least);
}

void basic_connection::process_packet(ipacket& in)
{
	opacket out;
	boost::system::error_code ec;
	
	switch ((message_type)m_packet)
	{
		case disconnect:
			if (m_connect_handler)
				m_connect_handler->handle_connect(error::make_error_code(error::connection_lost), m_io_service);
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
				
				handler->receive_and_post(move(m_packet), m_io_service);

				delete handler;
			}
			break;
	}
	
	if (ec and m_connect_handler)
		m_connect_handler->handle_connect(ec, m_io_service);
	else if (not out.empty())
	{
		async_write(out, [this](const boost::system::error_code& ec, size_t)
			{
				if (ec and m_connect_handler)
					m_connect_handler->handle_connect(ec, m_io_service);
			});
	}
}

opacket basic_connection::process_kexinit(ipacket& in, boost::system::error_code& ec)
{
	m_key_exchange = key_exchange::create(in, m_host_version, m_my_payload);

	opacket out;

	if (m_key_exchange == nullptr)
		ec = error::make_error_code(error::key_exchange_failed);
	else
		out = m_key_exchange->process_kexinit();
	
	return out;
}

opacket basic_connection::process_kexdhreply(ipacket& in, boost::system::error_code& ec)
{
	opacket out;
	
	if (m_key_exchange == nullptr)
		ec = error::make_error_code(error::key_exchange_failed);
	else
		out = m_key_exchange->process_kexdhreply(in, ec);
	
	return out;
}

opacket basic_connection::process_newkeys(ipacket& in, boost::system::error_code& ec)
{
	m_encryptor.reset(m_key_exchange->encryptor());
	m_decryptor.reset(m_key_exchange->decryptor());
	m_signer.reset(m_key_exchange->signer());
	m_verifier.reset(m_key_exchange->verifier());
	
	delete m_key_exchange;
	m_key_exchange = nullptr;

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

opacket basic_connection::process_service_accept(ipacket& in, boost::system::error_code& ec)
{
	opacket out(userauth_request);
	out << m_user << "ssh-connection" << "none";
	return out;
}

opacket basic_connection::process_userauth_success(ipacket& in, boost::system::error_code& ec)
{
	m_authenticated = true;
	m_connect_handler->handle_connect(boost::system::error_code(), m_io_service);

	delete m_connect_handler;
	m_connect_handler = nullptr;

	return opacket();
}

opacket basic_connection::process_userauth_failure(ipacket& in, boost::system::error_code& ec)
{
	string s;
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

opacket basic_connection::process_userauth_banner(ipacket& in, boost::system::error_code& ec)
{
	m_connect_handler->handle_connect(error::make_error_code(error::auth_cancelled_by_user), m_io_service);
	return opacket();
}

opacket basic_connection::process_userauth_info_request(ipacket& in, boost::system::error_code& ec)
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

void basic_connection::full_stop(const boost::system::error_code& ec)
{
	if (m_connect_handler)
		m_connect_handler->handle_connect(ec, m_io_service);
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

void basic_connection::async_write_packet_int(const opacket& p, basic_write_op* op)
{
	boost::asio::streambuf* request(new boost::asio::streambuf);

	{
		io::filtering_stream<io::output> out;
	
		if (m_encryptor)
			out.push(packet_encryptor(*m_encryptor, *m_signer, m_encryptor_cipher->BlockSize(), m_out_seq_nr));
		out.push(*request);

		p.write(out, m_blocksize);
	}

	++m_out_seq_nr;
	async_write_int(request, op);
}

}

