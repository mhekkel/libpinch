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

using namespace CryptoPP;
using namespace std;

namespace assh
{
	
class ssh_agent_impl
{
  public:
	static ssh_agent_impl&	instance();

	void			get_identities(vector<tuple<Integer,Integer,string>>& identities);
	vector<uint8_t>	sign(const vector<uint8_t>& blob, const vector<uint8_t>& data);
	
  private:
					ssh_agent_impl();
					~ssh_agent_impl();

	bool			process(const opacket& request, ipacket& reply);

	int				m_fd;
};

ssh_agent_impl&	ssh_agent_impl::instance()
{
	static ssh_agent_impl s_instance;
	return s_instance;
}

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

void ssh_agent_impl::get_identities(vector<tuple<Integer,Integer,string>>& identities)
{
	if (m_fd > 0)
	{
		ipacket reply;
		if (process(opacket((message_type)SSH2_AGENTC_REQUEST_IDENTITIES), reply) and
			reply.message() == (message_type)SSH2_AGENT_IDENTITIES_ANSWER)
		{
			uint32_t count;
			reply >> count;

			while (count-- > 0)
			{
				ipacket blob;
				string comment;
				
				reply >> blob >> comment;
				
				string type;
				blob >> type;
				
				if (type != "ssh-rsa")
					continue;
				
				Integer e, n;
				blob >> e >> n;
				
				identities.push_back(make_tuple(e, n, comment));
			}
		}
	}
}

vector<uint8_t> ssh_agent_impl::sign(const vector<uint8_t>& blob, const vector<uint8_t>& data)
{
	vector<uint8_t> digest;
	
	uint32_t flags = 0;
	opacket request((message_type)SSH2_AGENTC_SIGN_REQUEST);
	request << blob << data << flags;
	
	ipacket reply;
	if (process(request, reply) and reply.message() == (message_type)SSH2_AGENT_SIGN_RESPONSE)
		reply >> digest;
	
	return digest;
}

bool ssh_agent_impl::process(const opacket& request, ipacket& reply)
{
	bool result = false;
	
	const vector<uint8_t>& req(request);
	vector<uint8_t> rep;

	uint32_t l = htonl(req.size());
	
	if (write(m_fd, &l, sizeof(l)) == sizeof(l) and
		write(m_fd, req.data(), req.size()) == int32_t(req.size()) and
		read(m_fd, &l, sizeof(l)) == sizeof(l))
	{
		l = ntohl(l);
		
		if (l < 256 * 1024)	// sanity check
		{
			while (l > 0)
			{
				char b[1024];

				uint32_t k = l;
				if (k > sizeof(b))
					k = sizeof(b);
				
				if (read(m_fd, b, k) != k)
					break;
				
				rep.insert(rep.end(), b, b + k);
				
				l -= k;
			}
			
			result = (l == 0);
		}
	}
	
	if (result)
		reply = ipacket(rep.data(), rep.size());
	
	return result;
}

// --------------------------------------------------------------------

class posix_ssh_private_key_impl : public ssh_private_key_impl
{
  public:
		  					posix_ssh_private_key_impl(Integer& e, Integer& n, const string& comment);
	virtual					~posix_ssh_private_key_impl();

	virtual vector<uint8_t>	sign(const vector<uint8_t>& session_id, const opacket& p);

	virtual vector<uint8_t>	get_hash() const;
	virtual string			get_comment() const				{ return m_comment; }

  private:
	vector<uint8_t>			m_blob;
	string					m_comment;
};

posix_ssh_private_key_impl::posix_ssh_private_key_impl(Integer& e, Integer& n, const string& comment)
	: m_comment(comment)
{
	m_e = e;
	m_n = n;
	
	opacket blob;
	blob << "ssh-rsa" << m_e << m_n;
	m_blob = blob;
}

posix_ssh_private_key_impl::~posix_ssh_private_key_impl()
{
}

vector<uint8_t> posix_ssh_private_key_impl::sign(const vector<uint8_t>& session_id, const opacket& inData)
{
	const vector<uint8_t>& in_data(inData);
	vector<uint8_t> data(session_id);
	data.insert(data.end(), in_data.begin(), in_data.end());
	
	return ssh_agent_impl::instance().sign(m_blob, data);
}

vector<uint8_t> posix_ssh_private_key_impl::get_hash() const
{
	vector<uint8_t> hash;

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
//
//ssh_private_key_impl* ssh_private_key_impl::create_for_hash(const string& inHash)
//{
////	string hash;
////
////	Base64Decoder d(new StringSink(hash));
////	d.Put(reinterpret_cast<const byte*>(inHash.c_str()), inHash.length());
////	d.MessageEnd();
////	
//////	CRYPT_HASH_BLOB k;
//////	k.cbData = hash.length();
//////	k.pbData = const_cast<byte*>(reinterpret_cast<const byte*>(hash.c_str()));
//////	
//////	PCCERT_CONTEXT context = ::CertFindCertificateInStore(
//////		MCertificateStore::Instance(), X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
//////		0, CERT_FIND_SHA1_HASH, &k, nullptr);
//////	
//////	return new ssh_private_key_impl(context);
//
//	return nullptr;
//}

ssh_private_key_impl* ssh_private_key_impl::create_for_blob(ipacket& blob)
{
	ssh_private_key_impl* result = nullptr;

	string type;
	blob >> type;
	
	if (type == "ssh-rsa")
	{
		Integer e, n;
		blob >> e >> n;
		
		result = new posix_ssh_private_key_impl(e, n, "");
	}

	return result;
}

void ssh_private_key_impl::create_list(vector<ssh_private_key>& keys)
{
	vector<tuple<Integer,Integer,string>> identities;
	
	ssh_agent_impl::instance().get_identities(identities);
	
	for_each(identities.begin(), identities.end(),
		[&keys](tuple<Integer,Integer,string>& identity)
		{
			keys.push_back(new posix_ssh_private_key_impl(get<0>(identity),
				get<1>(identity), get<2>(identity)));
		});
}

}
