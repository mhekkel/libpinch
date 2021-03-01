//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <assh/config.hpp>

#include <cassert>
#include <regex>

#include <iterator>

#include <assh/ssh_agent.hpp>
#include <assh/detail/ssh_agent_impl.hpp>
#include <assh/packet.hpp>
#include <assh/connection.hpp>

#include <cryptopp/base64.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/queue.h>
#include <cryptopp/modes.h>
#include <cryptopp/asn.h>
#include <cryptopp/aes.h>
#include <cryptopp/camellia.h>
#include <cryptopp/idea.h>
#include <cryptopp/des.h>
#include <cryptopp/hex.h>
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>

#include <boost/algorithm/string.hpp>

using namespace std;
using namespace CryptoPP;
namespace ba = boost::algorithm;

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

	virtual vector<uint8_t>	sign(const vector<uint8_t>& session_id, const opacket& p);

	virtual vector<uint8_t>	get_hash() const	{ return vector<uint8_t>(); }
	virtual string			get_comment() const	{ return mComment; }

  private:
	RSA::PrivateKey			mPrivateKey;
	string					mComment;
};

vector<uint8_t> ssh_basic_private_key_impl::sign(const vector<uint8_t>& session_id, const opacket& p)
{
	AutoSeededRandomPool rng;

	vector<uint8_t> message(session_id);
	const vector<uint8_t>& data(p);
	message.insert(message.end(), data.begin(), data.end());
	
	RSASSA_PKCS1v15_SHA_Signer signer(mPrivateKey);
    size_t length = signer.MaxSignatureLength();
	vector<uint8_t> digest(length);

    signer.SignMessage(rng, message.data(), message.size(), digest.data());

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

vector<uint8_t> ssh_private_key::sign(const vector<uint8_t>& session_id, const opacket& data)
{
	return m_impl->sign(session_id, data);
}

vector<uint8_t> ssh_private_key::get_hash() const
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
			out = opacket(SSH_AGENT_RSA_IDENTITIES_ANSWER) << uint32_t(0);
			break;

		case SSH2_AGENTC_REQUEST_IDENTITIES:
		{
			out = opacket(SSH2_AGENT_IDENTITIES_ANSWER) << uint32_t(m_private_keys.size());
			
			for (auto& key: m_private_keys)
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
	list<vector<uint8_t>> deleted;
	
	for (ssh_private_key& key: m_private_keys)
		deleted.push_back(key.get_hash());
	
	m_private_keys.clear();
	ssh_private_key_impl::create_list(m_private_keys);
	
	for (ssh_private_key& key: m_private_keys)
		deleted.erase(remove(deleted.begin(), deleted.end(), key.get_hash()), deleted.end());
	
	connection_list connections(m_registered_connections);
	
	for (vector<uint8_t>& hash: deleted)
	{
		for (std::shared_ptr<connection_base> connection: connections)
		{
			if (connection->uses_private_key(hash))
				connection->disconnect();
		}
	}
}

void ssh_agent::register_connection(std::shared_ptr<connection_base> connection)
{
	if (find(m_registered_connections.begin(), m_registered_connections.end(), connection) == m_registered_connections.end())
		m_registered_connections.push_back(connection);
}

void ssh_agent::unregister_connection(std::shared_ptr<connection_base> connection)
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

struct ssh_known_ciper_for_private_key
{
	string							name;
	uint32_t						key_size;
	uint32_t						iv_size;
	function<SymmetricCipher*()>	factory;
} kKnownCiphers[] = {
	{ "AES-256-CBC", 32, 16,		[]() -> SymmetricCipher* { return new CBC_Mode<AES>::Decryption; }},
	{ "AES-192-CBC", 24, 16,		[]() -> SymmetricCipher* { return new CBC_Mode<AES>::Decryption; }},
	{ "AES-128-CBC", 16, 16,		[]() -> SymmetricCipher* { return new CBC_Mode<AES>::Decryption; }},
	{ "CAMELLIA-256-CBC", 32, 16,	[]() -> SymmetricCipher* { return new CBC_Mode<Camellia>::Decryption; }},
	{ "CAMELLIA-192-CBC", 24, 16,	[]() -> SymmetricCipher* { return new CBC_Mode<Camellia>::Decryption; }},
	{ "CAMELLIA-128-CBC", 16, 16,	[]() -> SymmetricCipher* { return new CBC_Mode<Camellia>::Decryption; }},
	{ "DES-EDE3-CBC", 24, 8,		[]() -> SymmetricCipher* { return new CBC_Mode<DES_EDE3>::Decryption; }},
	{ "IDEA-CBC", 16, 8,			[]() -> SymmetricCipher* { return new CBC_Mode<IDEA>::Decryption; }},
	{ "DES-CBC", 8, 8,				[]() -> SymmetricCipher* { return new CBC_Mode<DES>::Decryption; }}
};


// Signature changed a bit to match Crypto++. Salt must be PKCS5_SALT_LEN in length.
//  Salt, Data and Count are IN; Key and IV are OUT.
int OPENSSL_EVP_BytesToKey(HashTransformation& hash,
                           const unsigned char *salt, const unsigned char* data, int dlen,
                           unsigned int count, unsigned char *key, unsigned int ksize,
                           unsigned char *iv, unsigned int vsize);

// From OpenSSL, crypto/evp/evp.h.
static const unsigned int OPENSSL_PKCS5_SALT_LEN = 8;

// 64-character line length is required by RFC 1421.
// static const unsigned int RFC1421_LINE_BREAK = 64;
// static const unsigned int OPENSSL_B64_LINE_BREAK = 76;

// From crypto/evp/evp_key.h. Signature changed a bit to match Crypto++.
int OPENSSL_EVP_BytesToKey(HashTransformation& hash,
                           const unsigned char *salt, const unsigned char* data, int dlen,
                           unsigned int count, unsigned char *key, unsigned int ksize,
                           unsigned char *iv, unsigned int vsize)
{
    unsigned int niv,nkey,nhash;
    unsigned int addmd=0,i;
    
    nkey=ksize;
    niv=vsize;
    nhash=hash.DigestSize();
    
    SecByteBlock digest(hash.DigestSize());
    
    if (data == NULL) return (0);
    
    for (;;)
    {
        hash.Restart();
        
        if(addmd++)
            hash.Update(digest.data(), digest.size());
        
        hash.Update(data, dlen);
        
        if (salt != NULL)
            hash.Update(salt, OPENSSL_PKCS5_SALT_LEN);
        
        hash.TruncatedFinal(digest.data(), digest.size());
        
        for (i=1; i<count; i++)
        {
            hash.Restart();
            hash.Update(digest.data(), digest.size());
            hash.TruncatedFinal(digest.data(), digest.size());
        }
        
        i=0;
        if (nkey)
        {
            for (;;)
            {
                if (nkey == 0) break;
                if (i == nhash) break;
                if (key != NULL)
                    *(key++)=digest[i];
                nkey--;
                i++;
            }
        }
        if (niv && (i != nhash))
        {
            for (;;)
            {
                if (niv == 0) break;
                if (i == nhash) break;
                if (iv != NULL)
                    *(iv++)=digest[i];
                niv--;
                i++;
            }
        }
        if ((nkey == 0) && (niv == 0)) break;
    }
    
    return ksize;
}

void ssh_agent::add(const string& private_key, const string& key_comment, function<bool(string&)> provide_password)
{
	AutoSeededRandomPool prng;
	std::regex rx(
		"^-+BEGIN RSA PRIVATE KEY-+\\n"
		"(?:"
			"((?:^[^:]+:\\s*\\S.+\\n)+)"
		"\\n)?"
		"([ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\\s]+)=*\\n"
		"-+END RSA PRIVATE KEY-+\n?");
	
	std::smatch m;

	if (not std::regex_match(private_key, m, rx))
		throw runtime_error("Invalid PEM file");

	string keystr = m[2].str();
	string password;

	unique_ptr<SymmetricCipher> cipher;

	if (m[1].matched and provide_password(password))
	{
		// the keystr is probably encrypted
		string algo;
		string iv;
		
		stringstream s(m[1].str());
		for (;;)
		{
			string line;
			getline(s, line);
			
			if (line.empty())
				break;
			
			if (ba::starts_with(line, "Proc-Type:") and not ba::ends_with(line, "4,ENCRYPTED"))
			{
				algo.clear();
				break;
			}
			
			if (ba::starts_with(line, "DEK-Info:"))
			{
				string::size_type t = 9;
				while (t < line.length() and line[t] == ' ')
					++t;
				line.erase(0, t);
				t = line.find(',');
				algo = ba::to_upper_copy(line.substr(0, t));
				iv = line.substr(t + 1);
			}
		}
		
		for (auto c: kKnownCiphers)
		{
			if (c.name != algo)
				continue;
			
			HexDecoder hex;
			hex.Put((unsigned char*)iv.c_str(), iv.length());
			hex.MessageEnd();
			
			size_t iv_size = hex.MaxRetrievable();
			if (iv_size > c.iv_size)
				iv_size = c.iv_size;
			
			SecByteBlock key(c.key_size);
			SecByteBlock iv(iv_size);
			SecByteBlock salt(iv_size);
			
			hex.Get(iv.data(), iv.size());
			
			salt = iv;
			
			CryptoPP::Weak1::MD5 md5;
			(void)OPENSSL_EVP_BytesToKey(md5, iv.data(), (const unsigned char*)password.c_str(), password.length(),
				1, key.data(), key.size(), nullptr, 0);

			cipher.reset(c.factory());
			cipher->SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());
		}
	}

	string key;

	// Base64 decode, place in a ByteQueue    
	ByteQueue queue;
	Base64Decoder decoder;

	decoder.Attach(new Redirector(queue));
	decoder.Put((const unsigned char*)keystr.data(), keystr.length());
	decoder.MessageEnd();
	
	if (cipher)
	{
		ByteQueue temp;
		StreamTransformationFilter filter(*cipher, new Redirector(temp));
		queue.TransferTo(filter);
		filter.MessageEnd();
		
		queue = temp;
	}
	
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

// // --------------------------------------------------------------------

// ssh_agent_channel::ssh_agent_channel(std::shared_ptr<connection_base> connection)
// 	: channel(connection)
// {
// }

// ssh_agent_channel::~ssh_agent_channel()
// {
// }

// void ssh_agent_channel::opened()
// {
// 	channel::opened();
	
// 	opacket out(msg_channel_open_confirmation);
// 	out << m_host_channel_id << m_my_channel_id << m_my_window_size << kMaxPacketSize;
// 	m_connection->async_write(move(out));
// }

// void ssh_agent_channel::receive_data(const char* data, size_t size)
// {
// 	while (size > 0)
// 	{
// 		if (m_packet.empty() and size < 4)
// 		{
// 			close();	// we have an empty packet and less than 4 bytes... 
// 			break;		// simply fail this agent. I guess this should never happen
// 		}
		
// 		size_t r = m_packet.read(data, size);
		
// 		if (m_packet.complete())
// 		{
// 			opacket out;
// 			ssh_agent::instance().process_agent_request(m_packet, out);
// 			out = (opacket() << out);
// 			send_data(out);
			
// 			m_packet.clear();
// 		}
		
// 		data += r;
// 		size -= r;
// 	}
// }

}
