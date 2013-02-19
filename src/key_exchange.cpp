//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <assh/config.hpp>

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
#include <cryptopp/sha.h>

#include <assh/hash.hpp>
#include <assh/key_exchange.hpp>
#include <assh/error.hpp>
#include <assh/connection.hpp>

using namespace std;
using namespace CryptoPP;

namespace assh
{

static AutoSeededRandomPool	rng;

// --------------------------------------------------------------------
	
key_exchange::key_exchange(ipacket& in, const string& host_version,
		const vector<uint8>& my_payload, const vector<uint8>& host_payload)
	: m_host_version(host_version), m_my_payload(my_payload), m_host_payload(host_payload)
{
	bool first_kex_packet_follows;
	
	in	>> m_server_host_key_alg
		>> m_encryption_alg_c2s
		>> m_encryption_alg_s2c
		>> m_MAC_alg_c2s
		>> m_MAC_alg_s2c
		>> m_compression_alg_c2s
		>> m_compression_alg_s2c
		>> m_lang_c2s
		>> m_lang_s2c
		>> first_kex_packet_follows;
}

opacket key_exchange::process_kexdhreply(ipacket& in, boost::system::error_code& ec)
{
	ipacket hostkey, signature;
	Integer f;

	in >> hostkey >> f >> signature;
	
	calculate_hash(hostkey, f);

	if (m_session_id.empty())
		m_session_id = m_H;

	unique_ptr<PK_Verifier> h_key;

	string pk_type;
	ipacket pk_rs;
	signature >> pk_type >> pk_rs;

//						string hostName = mIPAddress;
//						if (mPortNumber != 22)
//							hostName = hostName + ':' + boost::lexical_cast<string>(mPortNumber);
//						if (not MKnownHosts::Instance().CheckHost(hostName, pk_type, hostkey))
//							Error(error::make_error_code(error::host_key_not_verifiable));

	string h_pk_type;
	hostkey >> h_pk_type;

	if (h_pk_type == "ssh-dss")
	{
		Integer h_p, h_q, h_g, h_y;
		hostkey >> h_p >> h_q >> h_g >> h_y;

		h_key.reset(new GDSA<SHA1>::Verifier(h_p, h_q, h_g, h_y));
	}
	else if (h_pk_type == "ssh-rsa")
	{
		Integer h_e, h_n;
		hostkey >> h_e >> h_n;

		h_key.reset(new RSASSA_PKCS1v15_SHA_Verifier(h_n, h_e));
	}

	const vector<uint8>& pk_rs_d(pk_rs);
	if (pk_type != h_pk_type or not h_key->VerifyMessage(&m_H[0], m_H.size(), &pk_rs_d[0], pk_rs_d.size()))
		ec = error::make_error_code(error::host_key_verification_failed);

	// derive the keys, 32 bytes should be enough
	int keylen = 32;
	for (int i = 0; i < 6; ++i)
	{
		vector<uint8> key = (hash<SHA1>() | m_K | m_H | ('A' + i) | m_session_id).final();
		
		for (int k = 20; k < keylen; k += 20)
		{
			vector<uint8> k2 = (hash<SHA1>() | m_K | m_H | key).final();
			key.insert(key.end(), k2.begin(), k2.end());
		}
		
		m_keys[i].assign(key.begin(), key.begin() + keylen);
	}

	return opacket(newkeys);	
}

StreamTransformation* key_exchange::decryptor()
{
	StreamTransformation* result = nullptr;
	
	// Server to client encryption
	string protocol = choose_protocol(m_encryption_alg_s2c, kEncryptionAlgorithms);
	
	if (protocol == "aes128-ctr")
		result = new CTR_Mode<AES>::Decryption(&m_keys[3][0], 16, &m_keys[1][0]);
	else if (protocol == "aes192-ctr")
		result = new CTR_Mode<AES>::Decryption(&keys[3][0], 24, &keys[1][0]);
	else if (protocol == "aes256-ctr")
		result = new CTR_Mode<AES>(&keys[3][0], 32, &keys[1][0]);
	else if (protocol == "3des-cbc")
		result = new CBC_Mode<DES_EDE3_Decryption>(&keys[3][0], &keys[1][0]);
	else if (protocol == "blowfish-cbc")
		result = new CBC_Mode<BlowfishDecryption>(&keys[3][0], &keys[1][0]);
	else if (protocol == "aes128-cbc")
		result = new CBC_Mode<AES>(&keys[3][0], 16, &keys[1][0]);
	else if (protocol == "aes192-cbc")
		result = new CBC_Mode<AES>(&keys[3][0], 24, &keys[1][0]);
	else if (protocol == "aes256-cbc")
		result = new CBC_Mode<AESDecryption>(&keys[3][0], 32, &keys[1][0]);
	
	return result;
}

StreamTransformation* key_exchange::encryptor()
{
	StreamTransformation* result = nullptr;
	
	// Client to server encryption
	string protocol = choose_protocol(m_encryption_alg_c2s, kEncryptionAlgorithms);
	
	if (protocol == "3des-cbc")
		result = new CBC_Mode<DES_EDE3>::Encryption(&m_keys[2][0], &m_keys[0][0]);
	else if (protocol == "blowfish-cbc")
		result = new CBC_Mode<BlowfishEncryption>(&m_keys[2][0], &m_keys[0][0]);
	else if (protocol == "aes128-cbc" or protocol == "aes128-ctr")
		result = new CBC_Mode<AES>(&m_keys[2][0], 16, &m_keys[0][0]);
	else if (protocol == "aes192-cbc")
		result = new CBC_Mode<AES>(&m_keys[2][0], 24, &m_keys[0][0]);
	else if (protocol == "aes256-cbc")
		result = new CBC_Mode<AES>(&m_keys[2][0], 32, &m_keys[0][0]);
	else if (protocol == "aes192-ctr")
		result = new CTR_Mode<AES>(&m_keys[2][0], 24, &m_keys[0][0]);
	else if (protocol == "aes256-ctr")
		result = new CTR_Mode<AES>(&m_keys[2][0], 32, &m_keys[0][0]);

	return result;	
}

MessageAuthenticationCode* key_exchange::signer()
{
	MessageAuthenticationCode* result = nullptr;

	string protocol = choose_protocol(m_MAC_alg_c2s, kMacAlgorithms);

	if (protocol == "hmac-sha1")
		result = new HMAC<SHA1>(&keys[4][0], 20);
	else
		result = new HMAC<Weak::MD5>(&keys[4][0]);
	
	return result;
}

MessageAuthenticationCode* key_exchange::verifier()
{
	MessageAuthenticationCode* result = nullptr;

	string protocol = choose_protocol(m_MAC_alg_s2c, kMacAlgorithms);
	if (protocol == "hmac-sha1")
		result = new HMAC<SHA1>(&keys[5][0], 20);
	else
		result = new HMAC<Weak::MD5>(&keys[5][0]);
	
	return result;
}

class key_exchange_dh_group1 : public key_exchange
{
  public:
							key_exchange_dh_group1(ipacket& in, const string& host_version,
								const vector<uint8>& my_payload, const vector<uint8>& host_payload)
								: key_exchange(in, host_version, my_payload, host_payload)
							{}

	virtual opacket			process_kexinit();
	virtual void			calculate_hash(ipacket& hostkey, Integer& f);
};

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
	};

const Integer
	p2(k_p_2, sizeof(k_p_2)),		q2((p2 - 1) / 2);

opacket key_exchange_dh_group1::process_kexinit()
{
	do
	{
		m_x.Randomize(rng, 2, q2 - 1);
		m_e = a_exp_b_mod_c(2, m_x, p2);
	}
	while (m_e < 1 or m_e >= p2 - 1);
	
	opacket out(kexdh_init);
	out << m_e;
	return out;
}

void key_exchange_dh_group1::calculate_hash(ipacket& hostkey, Integer& f)
{
	m_K = a_exp_b_mod_c(f, m_x, p2);

	opacket hp;
	hp << kSSHVersionString << m_host_version << m_my_payload << m_host_payload << hostkey << m_e << f << m_K;

	m_H = hash<SHA1>().update(hp).final();
}

class key_exchange_dh_group14 : public key_exchange
{
  public:
							key_exchange_dh_group14(ipacket& in, const string& host_version,
								const vector<uint8>& my_payload, const vector<uint8>& host_payload)
								: key_exchange(in, host_version, my_payload, host_payload)
							{}

	virtual opacket			process_kexinit();
	virtual void			calculate_hash(ipacket& hostkey, Integer& f);
};

static const byte
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

static const Integer
	p14(k_p_14, sizeof(k_p_14)),	q14((p14 - 1) / 2);

opacket key_exchange_dh_group14::process_kexinit()
{
	do
	{
		m_x.Randomize(rng, 2, q14 - 1);
		m_e = a_exp_b_mod_c(2, m_x, p14);
	}
	while (m_e < 1 or m_e >= p14 - 1);
	
	opacket out(kexdh_init);
	out << m_e;
	return out;
}

void key_exchange_dh_group14::calculate_hash(ipacket& hostkey, Integer& f)
{
	m_K = a_exp_b_mod_c(f, m_x, p2);

	opacket hp;
	hp << kSSHVersionString << m_host_version << m_my_payload << m_host_payload << hostkey << m_e << f << m_K;

	m_H = hash<SHA1>().update(hp).final();
}

//class key_exchange_dh_gex_sha1 : public key_exchange
//{
//  public:
//							key_exchange_dh_gex_sha1(ipacket& in,
//								const vector<uint8>& my_payload, const vector<uint8>& host_payload)
//								: key_exchange(in, my_payload, host_payload)
//							{}
//};
//
//class key_exchange_dh_gex_sha256 : public key_exchange
//{
//  public:
//							key_exchange_dh_gex_sha256(ipacket& in,
//								const vector<uint8>& my_payload, const vector<uint8>& host_payload)
//								: key_exchange(in, my_payload, host_payload)
//							{}
//};


key_exchange* key_exchange::create(ipacket& in, const string& host_version, const vector<uint8>& my_payload)
{
	// capture the packet contents for the host payload
	vector<uint8> host_payload = in;

	bool first_kex_packet_follows;
	in.skip(16);
	
	string algorithm;
	in >> algorithm;

	key_exchange* result = nullptr;

	if (algorithm == "diffie-hellman-group1-sha1")
		result = new key_exchange_dh_group1(in, host_version, my_payload, host_payload);
	else if (algorithm == "diffie-hellman-group14-sha1")
		result = new key_exchange_dh_group14(in, host_version, my_payload, host_payload);
//	else if (algorithm == "diffie-hellman-group-exchange-sha1")
//		result = new key_exchange_dh_gex_sha1(in, host_version, my_payload, host_payload);
//	else if (algorithm == "diffie-hellman-group-exchange-sha256")
//		result = new key_exchange_dh_gex_sha256(in, host_version, my_payload, host_payload);
	
	return result;
}


}
