//          Copyright Maarten L. Hekkelman 2006-2008
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <assh/config.hpp>

#include <iterator>

#include <boost/foreach.hpp>
#define foreach BOOST_FOREACH

#include <assh/ssh_agent.hpp>
#include <assh/detail/ssh_agent_impl.hpp>
#include <assh/packet.hpp>
#include <assh/connection.hpp>

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
// ssh_private_key

ssh_private_key::ssh_private_key(ssh_private_key_impl* impl)
	: m_impl(impl)
{
}

ssh_private_key::ssh_private_key(const string& hash)
	: m_impl(ssh_private_key_impl::create_for_hash(hash))
{
}

ssh_private_key::ssh_private_key(ipacket& blob)
	: m_impl(ssh_private_key_impl::create_for_blob(blob))
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

string ssh_private_key::get_hash() const
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

		case SSH_AGENTC_REQUEST_IDENTITIES:
		{
			out = opacket(SSH_AGENT_IDENTITIES_ANSWER) << uint32(m_private_keys.size());
			
			foreach (auto& key, m_private_keys)
			{
				opacket blob;
				blob << key;
				out << blob << key.get_comment();
			}
			break;
		}
		
		case SSH_AGENTC_SIGN_REQUEST:
		{
			ipacket blob, data;
			in >> blob >> data;
			
			ssh_private_key key(blob);
			
			if (key)
				out = opacket(SSH_AGENT_SIGN_RESPONSE) << key.sign(data, opacket());
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
	m_private_keys.clear();
	ssh_private_key_impl::create_list(m_private_keys);
}

// --------------------------------------------------------------------

ssh_agent_channel::ssh_agent_channel(basic_connection& connection)
	: channel(connection)
{
}

ssh_agent_channel::~ssh_agent_channel()
{
}

void ssh_agent_channel::setup(ipacket& in)
{
	m_channel_open = true;

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
