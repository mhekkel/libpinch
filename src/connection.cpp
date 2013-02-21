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

// --------------------------------------------------------------------

basic_connection::basic_connection(boost::asio::io_service& io_service, const string& user)
	: m_io_service(io_service)
	, m_user(user)
	, m_connect_handler(nullptr)
	, m_key_exchange(nullptr)
	, m_forward_agent(false)
{
}

basic_connection::~basic_connection()
{
	delete m_connect_handler;
	delete m_key_exchange;
}

void basic_connection::disconnect()
{
	m_authenticated = false;
	
	m_packet.clear();
	m_encryptor.reset(nullptr);
	m_decryptor.reset(nullptr);
	m_signer.reset(nullptr);
	m_verifier(nullptr);
	
	// copy the list since calling Close will change it
	list<channel*> channels(m_channels);
	for_each(channels.begin(), channels.end(), [](channel* c) { c->close(); });
}

void basic_connection::forward_agent(bool forward)
{
	m_forward_agent = forward;
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
			opacket out(msg_kexinit);
			
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
		
		switch ((message_type)m_packet)
		{
			case msg_disconnect:
				full_stop(error::make_error_code(error::connection_lost));
				break;

			case msg_kexinit:
				in.copy(m_host_payload);
				m_key_exchange = key_exchange::create(in, m_host_version, m_session_id, m_my_payload);
				m_key_exchange->process(in, out, ec);
				break;

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
	
	if (ec and m_connect_handler)
		m_connect_handler->handle_connect(ec, m_io_service);

	if (not out.empty())
	{
		async_write(out, [this](const boost::system::error_code& ec, size_t)
			{
				if (ec)
					full_stop(ec);
			});
	}
}

void basic_connection::process_newkeys(ipacket& in, opacket& out, boost::system::error_code& ec)
{
	m_encryptor.reset(m_key_exchange->encryptor());
	m_decryptor.reset(m_key_exchange->decryptor());
	m_signer.reset(m_key_exchange->signer());
	m_verifier.reset(m_key_exchange->verifier());
	
	delete m_key_exchange;
	m_key_exchange = nullptr;

	if (m_decryptor)
	{
		m_iblocksize = m_decryptor->OptimalBlockSize();
		m_oblocksize = m_encryptor->OptimalBlockSize();
	}
	
	if (not m_authenticated)
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
	m_connect_handler->handle_connect(boost::system::error_code(), m_io_service);

	delete m_connect_handler;
	m_connect_handler = nullptr;
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
	else if (choose_protocol(s, "password") == "password")
	{
		ec = error::make_error_code(error::require_password);
		out = msg_ignore;
	}
	else
		m_connect_handler->handle_connect(error::make_error_code(error::auth_cancelled_by_user), m_io_service);
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

		opacket signature;
		signature << "ssh-rsa" << ssh_private_key(blob).sign(session_id, out);

		out << signature;
	}
}

void basic_connection::full_stop(const boost::system::error_code& ec)
{
	disconnect();
	
	if (m_connect_handler)
		m_connect_handler->handle_connect(ec, m_io_service);
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

void basic_connection::async_write_packet_int(const opacket& p, basic_write_op* op)
{
	boost::asio::streambuf* request(new boost::asio::streambuf);

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

		ch->reference();
		m_channels.push_back(ch);
	}
	
	if (m_authenticated)
	{
		opacket out(msg_channel_open);
		out << "session" << channel_id << kWindowSize << kMaxPacketSize;
		async_write(out);
	}
}

void basic_connection::close_channel(channel* ch, uint32 channel_id)
{
	if (ch->is_open())
		ch->closed();

	if (m_authenticated)
	{
		opacket out(msg_channel_close);
		out << channel_id;
		async_write(out);
	}
	else if (find(m_channels.begin(), m_channels.end(), ch) != m_channels.end())
	{
		m_channels.erase(
			remove(m_channels.begin(), m_channels.end(), ch),
			m_channels.end());
	
		ch->release();
	}
}

void basic_connection::process_channel_open(ipacket& in, opacket& out)
{
	channel* c = nullptr;
	
	string type;
	uint32 host_channel_id;

	in >> type >> host_channel_id;

	try
	{
		//if (type == "x11")
		//	c = new x11_channel(*this);
		//else if (type == "auth-agent@openssh.com" and mForwardAgent)
		//	c = new ssh_agent_channel(*this);
	}
	catch (...) {}
	
	if (c != nullptr)
	{
		c->init(in, out);
		m_channels.push_back(c);
	}
	else
	{
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

//// data io for channels
//
//void basic_connection::send(opacket&& p)
//{
//	async_write(p, [this](const boost::system::error_code& ec, size_t)
//		{
//			if (ec and m_connect_handler)
//				m_connect_handler->handle_connect(ec, m_io_service);
//		});
//}

}

