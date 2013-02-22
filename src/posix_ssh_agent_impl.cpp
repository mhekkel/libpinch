//          Copyright Maarten L. Hekkelman 2006-2008
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <assh/config.hpp>

#include <sys/un.h>
#include <sys/socket.h>
#include <cerrno>
#include <fcntl.h>

#include <assh/ssh_agent.hpp>
#include <assh/detail/ssh_agent_impl.hpp>
#include <assh/packet.hpp>

#include <cryptopp/base64.h>

#include <boost/foreach.hpp>
#define foreach BOOST_FOREACH

using namespace CryptoPP;
using namespace std;

namespace assh
{
	
enum
{
	/* Messages for the authentication agent connection. */
	SSH_AGENTC_REQUEST_RSA_IDENTITIES =	1,
	SSH_AGENT_RSA_IDENTITIES_ANSWER,
	SSH_AGENTC_RSA_CHALLENGE,
	SSH_AGENT_RSA_RESPONSE,
	SSH_AGENT_FAILURE,
	SSH_AGENT_SUCCESS,
	SSH_AGENTC_ADD_RSA_IDENTITY,
	SSH_AGENTC_REMOVE_RSA_IDENTITY,
	SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES,
	
	/* private OpenSSH extensions for SSH2 */
	SSH2_AGENTC_REQUEST_IDENTITIES = 11,
	SSH2_AGENT_IDENTITIES_ANSWER,
	SSH2_AGENTC_SIGN_REQUEST,
	SSH2_AGENT_SIGN_RESPONSE,
	SSH2_AGENTC_ADD_IDENTITY = 17,
	SSH2_AGENTC_REMOVE_IDENTITY,
	SSH2_AGENTC_REMOVE_ALL_IDENTITIES,
	
	/* smartcard */
	SSH_AGENTC_ADD_SMARTCARD_KEY,
	SSH_AGENTC_REMOVE_SMARTCARD_KEY,
	
	/* lock/unlock the agent */
	SSH_AGENTC_LOCK,
	SSH_AGENTC_UNLOCK,
	
	/* add key with constraints */
	SSH_AGENTC_ADD_RSA_ID_CONSTRAINED,
	SSH2_AGENTC_ADD_ID_CONSTRAINED,
	SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED,
	
	SSH_AGENT_CONSTRAIN_LIFETIME = 1,
	SSH_AGENT_CONSTRAIN_CONFIRM,
	
	/* extended failure messages */
	SSH2_AGENT_FAILURE = 30,
	
	/* additional error code for ssh.com's ssh-agent2 */
	SSH_COM_AGENT2_FAILURE = 102,
	
	SSH_AGENT_OLD_SIGNATURE = 0x01
};

class ssh_agent_impl
{
  public:
	static ssh_agent_impl&	instance();

	void			get_identities(vector<tr1::tuple<Integer,Integer,string>>& identities);
	vector<uint8>	sign(const vector<uint8>& blob, const vector<uint8>& data);
	
  private:
					ssh_agent_impl();
					~ssh_agent_impl();

	bool			process(opacket& request, ipacket& reply);

	int				m_fd;
};

ssh_agent_impl::ssh_agent_impl()
	: m_fd(-1)
{
	const char* authSock = getenv("SSH_AUTH_SOCK");
	
	if (authSock != nullptr)
	{
		struct sockaddr_un addr = {};
		addr.sun_family = AF_LOCAL;
		strcpy(addr.sun_path, authSock);
		
		int sock = socket(AF_LOCAL, SOCK_STREAM, 0);
		if (sock >= 0)
		{
			if (fcntl(sock, F_SETFD, 1) < 0)
				close(sock);
			else if (connect(sock, (const sockaddr*)&addr, sizeof(addr)) < 0)
				close(sock);
			else
				m_fd = sock;
		}
	}
}

ssh_agent_impl::~ssh_agent_impl()
{
	if (m_fd >= 0)
		close(m_fd);
}

void ssh_agent_impl::get_identities(vector<tr1::tuple<Integer,Integer,string>>& identities)
{
	if (m_fd > 0)
	{
		ipacket reply;
		if (process(opacket((message_type)SSH2_AGENTC_REQUEST_IDENTITIES), reply) and
			reply == (message_type)SSH2_AGENT_IDENTITIES_ANSWER)
		{
			uint32 count;
			reply >> count;

			while (count-- > 0)
			{
				ipacket blob;
				string comment;
				
				reply >> blob >> comment;
				
				string type;
				reply >> type;
				
				if (type != "ssh-rsa")
					continue;
				
				Integer e, n;
				reply >> e >> n;
				
				identities.push_back(tr1::make_tuple(e, n, comment));
			}
		}
	}
}

vector<uint8> ssh_agent_impl::sign(const vector<uint8>& blob, const vector<uint8>& data)
{
	vector<uint8> digest;
	
	uint32 flags = 0;
	opacket request((message_type)SSH2_AGENTC_SIGN_REQUEST);
	request << blob << data << flags;
	
	ipacket reply;
	if (RequestReply(request, reply) and reply == (message_type)SSH2_AGENT_SIGN_RESPONSE)
		reply >> digest;
	
	return digest;
}

bool ssh_agent_impl::process(opacket& request, ipacket& reply)
{
	bool result = false;
	
	uint32 l = htonl(out.size());
	
	const vector<uint8>& req(request);
	vector<uint8> rep;
	
	if (write(m_fd, &l, sizeof(l)) == sizeof(l) and
		write(m_fd, &req[0], req.size()) == int32(req.size()) and
		read(m_fd, &l, sizeof(l)) == sizeof(l))
	{
		l = ntohl(l);
		
		if (l < 256 * 1024)	// sanity check
		{
			char b[1024];

			uint32 k = l;
			if (k > sizeof(b))
				k = sizeof(b);
			
			while (l > 0)
			{
				if (read(m_fd, b, k) != k)
					break;
				
				rep.append(b, k);
				
				l -= k;
			}
			
			result = (l == 0);
		}
	}
	
	if (result)
		reply = ipacket(&rep[0], rep.size());
	
	return result;
}

// --------------------------------------------------------------------

class ssh_private_key_impl : public ssh_private_key_impl
{
  public:
		  					ssh_private_key_impl(Integer& e, Integer& n, const string& comment);
	virtual					~ssh_private_key_impl();

	virtual vector<uint8>	sign(const vector<uint8>& session_id, const opacket& p);

	virtual string			get_hash() const;
	virtual string			get_comment() const				{ return m_comment; }

  private:
	vector<uint8>			m_blob;
	string					m_comment;
};

ssh_private_key_impl::ssh_private_key_impl(Integer& e, Integer& n,
		const string& comment, const vector<uint8>& blob)
	: m_comment(comment)
{
	m_e = e;
	m_n = n;
	
	opacket blob;
	blob << "ssh-rsa" << m_e << m_n;
	m_blob = blob;
}

ssh_private_key_impl::~ssh_private_key_impl()
{
}

vector<uint8> ssh_private_key_impl::sign(const vector<uint8>& session_id, const opacket& inData)
{
	const vector<uint8>& in_data(inData);
	vector<uint8> data(session_id);
	data.insert(data.end(), in_data.begin(), in_data.end());
	
	return ssh_agent_impl::instance().sign(m_blob, data);
}

string ssh_private_key_impl::get_hash() const
{
	string hash;

//	// and create a hash for this key
//	byte sha1[20];	// SHA1 hash is always 20 bytes
//	DWORD cbHash = sizeof(sha1);
//			
//	if (::CertGetCertificateContextProperty(mCertificateContext,
//		CERT_HASH_PROP_ID, sha1, &cbHash))
//	{
//		Base64Encoder enc(new StringSink(hash));
//		enc.Put(sha1, cbHash);
//		enc.MessageEnd(true);
//	}

	return hash;
}

// --------------------------------------------------------------------

ssh_private_key_impl* ssh_private_key_impl::create_for_hash(const string& inHash)
{
//	string hash;
//
//	Base64Decoder d(new StringSink(hash));
//	d.Put(reinterpret_cast<const byte*>(inHash.c_str()), inHash.length());
//	d.MessageEnd();
//	
////	CRYPT_HASH_BLOB k;
////	k.cbData = hash.length();
////	k.pbData = const_cast<byte*>(reinterpret_cast<const byte*>(hash.c_str()));
////	
////	PCCERT_CONTEXT context = ::CertFindCertificateInStore(
////		MCertificateStore::Instance(), X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
////		0, CERT_FIND_SHA1_HASH, &k, nullptr);
////	
////	return new ssh_private_key_impl(context);

	return nullptr;
}

ssh_private_key_impl* ssh_private_key_impl::create_for_blob(ipacket& blob)
{
	ssh_private_key_impl* result = nullptr;

	string type;
	blob >> type;
	
	if (type == "ssh-rsa")
	{
		Integer e, n;
		blob >> e >> n;
		
		result = new ssh_private_key_impl(e, n, "");
	}

	return result;
}

void ssh_private_key_impl::create_list(vector<ssh_private_key>& keys)
{
	vector<tr1::tuple<Integer,Integer,string>> identities;
	
	ssh_agent_impl::instance().get_identities(identities);
	
	for_each(identities.begin(), identities.end(),
		[&keys](tr1::tuple<Integer,Integer,string>& identity)
		{
			keys.push_back(new ssh_private_key_impl(tr1::get<0>(identity),
				tr1::get<1>(identity), tr1::get<2>(identity)));
		});
}

}
