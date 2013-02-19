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

vector<uint8> ssh_private_key::sign(const vector<uint8>& session_id, const opacket& p)
{
	return m_impl->sign(session_id, p);
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

//void ssh_agent::process_agent_request(opacket& in, opacket& out)
//{
//	uint8 msg;
//	in >> msg;
//
//	switch (msg)
//	{
//		case SSH_AGENTC_REQUEST_IDENTITIES:
//		{
//			out << uint8(SSH_AGENT_IDENTITIES_ANSWER) << uint32(m_private_keys.size());
//			
//			for (ssh_private_keyList::iterator key = m_private_keys.begin(); key != m_private_keys.end(); ++key)
//			{
//				opacket blob;
//				blob << *key;
//				out << blob << key->get_comment();
//			}
//			break;
//		}
//		
//		case SSH_AGENTC_SIGN_REQUEST:
//		{
//			ipacket blob, data;
//			in >> blob >> data;
//			
//			ssh_private_key key(blob);
//			
//			if (key)
//			{
//				vector<uint8> sigdata;
//				key.SignData(data, sigdata);
//		
//				opacket signature;
//				signature << "ssh-rsa" << sigdata;
//				out << uint8(SSH_AGENT_SIGN_RESPONSE) << signature;
//			}
//			else
//				out << uint8(SSH_AGENT_FAILURE);
//			break;
//		}
//		
//		default:
//			out << uint8(SSH_AGENT_FAILURE);
//			break;
//	}
//}

void ssh_agent::update()
{
	m_private_keys.clear();
	ssh_private_key_impl::create_list(m_private_keys);
}

//// --------------------------------------------------------------------
//
//ssh_agentChannel::ssh_agentChannel(MSshConnection& inConnection)
//	: MSshChannel(inConnection)
//	, mPacketLength(0)
//{
//}
//
//ssh_agentChannel::~ssh_agentChannel()
//{
//}
//
//void ssh_agentChannel::Setup(opacket& in)
//{
//	mChannelOpen = true;
//
//	opacket out;
//	out << uint8(SSH_MSG_CHANNEL_OPEN_CONFIRMATION) << mHostChannelID
//		<< mMyChannelID << mMyWindowSize << kMaxPacketSize;
//	Send(out);
//}
//
//void ssh_agentChannel::ReceiveData(opacket& inData)
//{
//	copy(inData.peek(), inData.peek() + inData.size(), back_inserter(mPacket));
//
//	while (not mPacket.empty())
//	{
//		if (mPacketLength > 0 and mPacketLength <= mPacket.size())
//		{
//			opacket in(mPacket, mPacketLength), out;
//
//			mPacket.erase(mPacket.begin(), mPacket.begin() + mPacketLength);
//			mPacketLength = 0;
//
//			ssh_agent::Instance().ProcessAgentRequest(in, out);
//			
//			opacket d2;
//			d2 << out;
//			MSshChannel::SendData(d2);
//			continue;
//		}
//		
//		if (mPacketLength == 0 and mPacket.size() >= sizeof(uint32))
//		{
//			for (uint32 i = 0; i < 4; ++i)
//			{
//				mPacketLength = mPacketLength << 8 | mPacket.front();
//				mPacket.pop_front();
//			}
//			
//			continue;
//		}
//		
//		break;
//	}
//}

}
