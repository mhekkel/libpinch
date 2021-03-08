//          Copyright Maarten L. Hekkelman 2006-2008
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <pinch/pinch.hpp>

#include <sys/un.h>
#include <sys/socket.h>
#include <cerrno>
#include <fcntl.h>
#include <netinet/in.h>

#include <pinch/ssh_agent.hpp>
#include <pinch/detail/ssh_agent_impl.hpp>
#include <pinch/packet.hpp>

using namespace CryptoPP;

namespace pinch
{

class ssh_agent_impl
{
public:
	static ssh_agent_impl &instance();

	void get_identities(std::vector<std::tuple<Integer, Integer, std::string>> &identities);
	blob sign(const blob &b, const blob &data);

private:
	ssh_agent_impl();
	~ssh_agent_impl();

	bool process(const opacket &request, ipacket &reply);

	int m_fd;
};

ssh_agent_impl &ssh_agent_impl::instance()
{
	static ssh_agent_impl s_instance;
	return s_instance;
}

ssh_agent_impl::ssh_agent_impl()
	: m_fd(-1)
{
	const char *authSock = getenv("SSH_AUTH_SOCK");

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
			else if (connect(sock, (const sockaddr *)&addr, sizeof(addr)) < 0)
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

void ssh_agent_impl::get_identities(std::vector<std::tuple<Integer, Integer, std::string>> &identities)
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
				std::string comment;

				reply >> blob >> comment;

				std::string type;
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

blob ssh_agent_impl::sign(const blob &b, const blob &data)
{
	blob digest;

	uint32_t flags = 0;
	opacket request((message_type)SSH2_AGENTC_SIGN_REQUEST);
	request << b << data << flags;

	ipacket reply;
	if (process(request, reply) and reply.message() == (message_type)SSH2_AGENT_SIGN_RESPONSE)
		reply >> digest;

	return digest;
}

bool ssh_agent_impl::process(const opacket &request, ipacket &reply)
{
	bool result = false;

	const blob &req(request);
	blob rep;

	uint32_t l = htonl(req.size());

	if (write(m_fd, &l, sizeof(l)) == sizeof(l) and
		write(m_fd, req.data(), req.size()) == int32_t(req.size()) and
		read(m_fd, &l, sizeof(l)) == sizeof(l))
	{
		l = ntohl(l);

		if (l < 256 * 1024) // sanity check
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
	posix_ssh_private_key_impl(const Integer &e, const Integer &n, const std::string &comment);
	virtual ~posix_ssh_private_key_impl();

	virtual blob sign(const blob &session_id, const opacket &p);

	virtual blob get_hash() const;
	virtual std::string get_comment() const { return m_comment; }

  private:
	blob m_blob;
	std::string m_comment;
};

posix_ssh_private_key_impl::posix_ssh_private_key_impl(const Integer &e, const Integer &n, const std::string &comment)
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

blob posix_ssh_private_key_impl::sign(const blob &session_id, const opacket &inData)
{
	const blob &in_data(inData);
	blob data(session_id);
	data.insert(data.end(), in_data.begin(), in_data.end());

	return ssh_agent_impl::instance().sign(m_blob, data);
}

blob posix_ssh_private_key_impl::get_hash() const
{
	blob hash;

	//	// and create a hash for this key
	//	uint8_t sha1[20];	// SHA1 hash is always 20 bytes
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
////	d.Put(reinterpret_cast<const uint8_t*>(inHash.c_str()), inHash.length());
////	d.MessageEnd();
////
//////	CRYPT_HASH_BLOB k;
//////	k.cbData = hash.length();
//////	k.pbData = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(hash.c_str()));
//////
//////	PCCERT_CONTEXT context = ::CertFindCertificateInStore(
//////		MCertificateStore::Instance(), X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
//////		0, CERT_FIND_SHA1_HASH, &k, nullptr);
//////
//////	return new ssh_private_key_impl(context);
//
//	return nullptr;
//}

ssh_private_key_impl *ssh_private_key_impl::create_for_blob(ipacket &blob)
{
	ssh_private_key_impl *result = nullptr;

	std::string type;
	blob >> type;

	if (type == "ssh-rsa")
	{
		Integer e, n;
		blob >> e >> n;

		result = new posix_ssh_private_key_impl(e, n, "");
	}

	return result;
}

void ssh_private_key_impl::create_list(std::vector<ssh_private_key> &keys)
{
	std::vector<std::tuple<Integer, Integer, std::string>> identities;

	ssh_agent_impl::instance().get_identities(identities);

	for (const auto& [e, n, comment]: identities)
		keys.emplace_back(new posix_ssh_private_key_impl(e, n, comment));
}

}
