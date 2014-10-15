//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <assh/config.hpp>

#include <cassert>

#include <iterator>

#include <boost/foreach.hpp>
#define foreach BOOST_FOREACH
#include <boost/regex.hpp>

#include <assh/ssh_agent.hpp>
#include <assh/detail/ssh_agent_impl.hpp>
#include <assh/packet.hpp>
#include <assh/connection.hpp>

#include <cryptopp/base64.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>

using namespace std;
using namespace CryptoPP;

namespace assh
{

// --------------------------------------------------------------------
// ssh_private_key_impl

ssh_private_key_impl::ssh_private_key_impl()
	: m_refcount(1)
{
}

ssh_private_key_impl::~ssh_private_key_impl()
{
	assert(m_refcount == 0);
}

void ssh_private_key_impl::reference()
{
	++m_refcount;
}

void ssh_private_key_impl::release()
{
	if (--m_refcount == 0)
		delete this;
}

// --------------------------------------------------------------------
// ssh_basic_private_key_impl

class ssh_basic_private_key_impl : public ssh_private_key_impl
{
  public:
		  					ssh_basic_private_key_impl(RSA::PrivateKey& rsa, const string& comment)
								: mPrivateKey(rsa), mComment(comment)
		  					{
		  						m_e = mPrivateKey.GetPublicExponent();
		  						m_n = mPrivateKey.GetModulus();
		  					}

	virtual vector<uint8>	sign(const vector<uint8>& session_id, const opacket& p);

	virtual vector<uint8>	get_hash() const	{ return vector<uint8>(); }
	virtual string			get_comment() const	{ return mComment; }

  private:
	RSA::PrivateKey			mPrivateKey;
	string					mComment;
};

vector<uint8> ssh_basic_private_key_impl::sign(const vector<uint8>& session_id, const opacket& p)
{
	AutoSeededRandomPool rng;

	vector<uint8> message(session_id);
	const vector<uint8>& data(p);
	message.insert(message.end(), data.begin(), data.end());
	
	RSASSA_PKCS1v15_SHA_Signer signer(mPrivateKey);
    size_t length = signer.MaxSignatureLength();
	vector<uint8> digest(length);

    signer.SignMessage(rng, &message[0], message.size(), &digest[0]);

	opacket signature;
	signature << "ssh-rsa" << digest;
	return signature;
}

// --------------------------------------------------------------------
// ssh_private_key

ssh_private_key::ssh_private_key(ssh_private_key_impl* impl)
	: m_impl(impl)
{
}

ssh_private_key::ssh_private_key(const ssh_private_key& inKey)
	: m_impl(inKey.m_impl)
{
	m_impl->reference();
}

ssh_private_key::~ssh_private_key()
{
	m_impl->release();
}

ssh_private_key& ssh_private_key::operator=(const ssh_private_key& inKey)
{
	if (this != &inKey)
	{
		m_impl->release();
		m_impl = inKey.m_impl;
		m_impl->reference();
	}
	
	return *this;
}

vector<uint8> ssh_private_key::sign(const vector<uint8>& session_id, const opacket& data)
{
	return m_impl->sign(session_id, data);
}

vector<uint8> ssh_private_key::get_hash() const
{
	return m_impl->get_hash();
}

string ssh_private_key::get_comment() const
{
	return m_impl->get_comment();
}

opacket& operator<<(opacket& p, const ssh_private_key& key)
{
	p << "ssh-rsa" << key.m_impl->m_e << key.m_impl->m_n;
	return p;
}

// --------------------------------------------------------------------

ssh_agent& ssh_agent::instance()
{
	static ssh_agent s_instance;
	return s_instance;
}

ssh_agent::ssh_agent()
{
	update();
}

ssh_agent::~ssh_agent()
{
	m_private_keys.clear();
}

void ssh_agent::process_agent_request(ipacket& in, opacket& out)
{
	switch ((message_type)in)
	{
		case SSH_AGENTC_REQUEST_RSA_IDENTITIES:
			out = opacket(SSH_AGENT_RSA_IDENTITIES_ANSWER) << uint32(0);
			break;

		case SSH2_AGENTC_REQUEST_IDENTITIES:
		{
			out = opacket(SSH2_AGENT_IDENTITIES_ANSWER) << uint32(m_private_keys.size());
			
			foreach (auto& key, m_private_keys)
			{
				opacket blob;
				blob << key;
				out << blob << key.get_comment();
			}
			break;
		}
		
		case SSH2_AGENTC_SIGN_REQUEST:
		{
			ipacket blob, data;
			in >> blob >> data;
			
			ssh_private_key key = get_key(blob);
			
			if (key)
				out = opacket(SSH2_AGENT_SIGN_RESPONSE) << key.sign(data, opacket());
			else
				out = opacket(SSH_AGENT_FAILURE);
			break;
		}
		
		default:
			out = opacket(SSH_AGENT_FAILURE);
			break;
	}
}

void ssh_agent::update()
{
	list<vector<uint8>> deleted;
	
	foreach (ssh_private_key& key, m_private_keys)
		deleted.push_back(key.get_hash());
	
	m_private_keys.clear();
	ssh_private_key_impl::create_list(m_private_keys);
	
	foreach (ssh_private_key& key, m_private_keys)
		deleted.erase(remove(deleted.begin(), deleted.end(), key.get_hash()), deleted.end());
	
	connection_list connections(m_registered_connections);
	
	foreach (vector<uint8>& hash, deleted)
	{
		foreach (basic_connection* connection, connections)
		{
			if (connection->get_used_private_key() == hash)
				connection->disconnect();
		}
	}
}

void ssh_agent::register_connection(basic_connection* connection)
{
	if (find(m_registered_connections.begin(), m_registered_connections.end(), connection) == m_registered_connections.end())
		m_registered_connections.push_back(connection);
}

void ssh_agent::unregister_connection(basic_connection* connection)
{
	m_registered_connections.erase(
		remove(m_registered_connections.begin(), m_registered_connections.end(), connection),
		m_registered_connections.end());
}

void ssh_agent::expose_pageant(bool expose)
{
#if defined(_MSC_VER)
	assh::expose_pageant(expose);
#endif
}

void ssh_agent::add(const string& private_key, const string& key_comment)
{
	AutoSeededRandomPool prng;
	boost::regex rx("^-+BEGIN RSA PRIVATE KEY-+\n(.+)\n-+END RSA PRIVATE KEY-+\n?");

	boost::smatch m;

	if (not boost::regex_match(private_key, m, rx))
		throw runtime_error("Invalid PEM file");

	string keystr = m[1].str();
	string key;

	// Base64 decode, place in a ByteQueue    
	ByteQueue queue;
	Base64Decoder decoder;

	decoder.Attach(new Redirector(queue));
	decoder.Put((const byte*)keystr.data(), keystr.length());
	decoder.MessageEnd();

	RSA::PrivateKey rsaPrivate;
	rsaPrivate.BERDecodePrivateKey(queue, false /*paramsPresent*/, queue.MaxRetrievable());

	if (not queue.IsEmpty() or not rsaPrivate.Validate(prng, 3))
		throw runtime_error("RSA private key is not valid");

	m_private_keys.push_back(ssh_private_key(new ssh_basic_private_key_impl(rsaPrivate, key_comment)));
}

ssh_private_key ssh_agent::get_key(ipacket& blob) const
{
	for (auto& key: m_private_keys)
	{
		opacket b;
		b << key;
		
		if (blob == b)
			return key;
	}
	
	throw runtime_error("private key not found");
}

// --------------------------------------------------------------------

ssh_agent_channel::ssh_agent_channel(basic_connection& connection)
	: channel(connection)
{
}

ssh_agent_channel::~ssh_agent_channel()
{
}

void ssh_agent_channel::opened()
{
	channel::opened();
	
	opacket out(msg_channel_open_confirmation);
	out << m_host_channel_id << m_my_channel_id << m_my_window_size << kMaxPacketSize;
	m_connection.async_write(move(out));
}

void ssh_agent_channel::receive_data(const char* data, size_t size)
{
	while (size > 0)
	{
		if (m_packet.empty() and size < 4)
		{
			close();	// we have an empty packet and less than 4 bytes... 
			break;		// simply fail this agent. I guess this should never happen
		}
		
		size_t r = m_packet.read(data, size);
		
		if (m_packet.complete())
		{
			opacket out;
			ssh_agent::instance().process_agent_request(m_packet, out);
			out = (opacket() << out);
			send_data(out);
			
			m_packet.clear();
		}
		
		data += r;
		size -= r;
	}
}

}
