//        Copyright Maarten L. Hekkelman 2013-2021
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <pinch/pinch.hpp>

#include <cryptopp/aes.h>
#include <cryptopp/des.h>
#include <cryptopp/dsa.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/factory.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/gfpcrypt.h>
#include <cryptopp/modes.h>
#include <cryptopp/oids.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>

#include <pinch/channel.hpp>
#include <pinch/crypto-engine.hpp>

using namespace CryptoPP;

namespace pinch
{

static AutoSeededRandomPool rng;

// --------------------------------------------------------------------

const std::string
	kKeyExchangeAlgorithms("diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256"),
	kServerHostKeyAlgorithms("ecdsa-sha2-nistp256" /* ",rsa-sha2-512,rsa-sha2-256" */ ",ssh-rsa"),
	kEncryptionAlgorithms("aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,aes192-cbc,aes256-cbc,3des-cbc"),
	kMacAlgorithms("hmac-sha2-512,hmac-sha2-256"),
	kCompressionAlgorithms("zlib@openssh.com,zlib,none");

// --------------------------------------------------------------------

std::string choose_protocol(const std::string &server, const std::string &client)
{
	std::string result;
	bool found = false;

	std::string::size_type ci = 0, cn = client.find(',');
	while (not found)
	{
		auto cp = client.substr(ci, cn - ci);

		std::string::size_type si = 0, sn = server.find(',');
		while (not found)
		{
			auto sp = server.substr(si, sn - si);

			if (cp == sp)
			{
				result = cp;
				found = true;
				break;
			}

			if (sn == std::string::npos)
				break;

			si = sn + 1;
			sn = server.find(',', si);
		}

		if (found or cn == std::string::npos)
			break;

		ci = cn + 1;
		cn = client.find(',', ci);
	}

	return result;
}

// --------------------------------------------------------------------
// a utility class to make hashing easier

template <typename HAlg>
class hash
{
  public:
	hash() {}

	hash &update(const CryptoPP::Integer &v)
	{
		opacket p;
		p << v;
		return update(static_cast<blob>(p));
	}

	hash &update(const blob &v)
	{
		m_hash.Update(v.data(), v.size());
		return *this;
	}

	hash &update(const std::string &v)
	{
		m_hash.Update(reinterpret_cast<const uint8_t *>(v.c_str()), v.length());
		return *this;
	}

	hash &update(const char *v)
	{
		m_hash.Update(v, std::strlen(v));
		return *this;
	}

	hash &update(uint8_t v)
	{
		m_hash.Update(&v, 1);
		return *this;
	}

	blob final()
	{
		blob result(m_hash.DigestSize());
		m_hash.Final(result.data());
		return result;
	}

  private:
	hash(const hash &);
	hash &operator=(const hash &);

	HAlg m_hash;
};

template <typename H, typename T>
hash<H> &operator|(hash<H> &h, T t)
{
	return h.update(t);
}

// --------------------------------------------------------------------

struct key_exchange_impl
{
	key_exchange_impl(key_exchange &kx)
		: m_kx(kx)
		, m_host_payload(m_kx.m_host_payload)
		, m_my_payload(m_kx.m_my_payload)
	{
	}

	virtual ~key_exchange_impl() = default;

	virtual void calculate_hash(const std::string &host_version, ipacket &hostkey, CryptoPP::Integer &f) = 0;

	virtual bool process(ipacket &in, opacket &out, boost::system::error_code &ec)
	{
		bool handled = true;

		switch ((message_type)in)
		{
			case msg_kex_dh_reply:
			case msg_kex_dh_gex_reply:
				process_kex_dh_reply(in, out, ec);
				break;

			default:
				handled = false;
				break;
		}

		return handled;
	}

	template <typename HashAlgorithm>
	void do_derive_keys()
	{
		// derive the keys, 64 bytes should be enough
		int keylen = 64;
		for (int i = 0; i < 6; ++i)
		{
			hash<HashAlgorithm> ha;
			blob key = (ha | m_K | m_H | ('A' + i) | m_kx.m_session_id).final();

			for (int k = 20; k < keylen; k += 20)
			{
				blob k2 = (ha | m_K | m_H | key).final();
				key.insert(key.end(), k2.begin(), k2.end());
			}

			m_keys[i].assign(key.begin(), key.begin() + keylen);
		}
	}

	void process_kex_dh_reply(ipacket &in, opacket &out, boost::system::error_code &ec);

	virtual void derive_keys() = 0;

	key_exchange &m_kx;
	blob m_H, m_keys[6];
	blob &m_host_payload, &m_my_payload;
	CryptoPP::Integer m_x, m_e, m_K, m_p, m_q, m_g;
};

void key_exchange_impl::process_kex_dh_reply(ipacket &in, opacket &out, boost::system::error_code &ec)
{
	ipacket hostkey, signature;
	Integer f;

	in >> hostkey >> f >> signature;

	m_K = a_exp_b_mod_c(f, m_x, m_p);

	calculate_hash(m_kx.m_host_version, hostkey, f);

	if (m_kx.m_session_id.empty())
		m_kx.m_session_id = m_H;

	std::unique_ptr<PK_Verifier> h_key;

	ipacket pk_rs;
	signature >> m_kx.m_pk_type;
	m_kx.m_host_key = hostkey;

	std::string h_pk_type;
	hostkey >> h_pk_type;

	blob pk_rs_d;

	if (h_pk_type == "ssh-dss")
	{
		Integer h_p, h_q, h_g, h_y;
		hostkey >> h_p >> h_q >> h_g >> h_y;

		h_key.reset(new GDSA<SHA1>::Verifier(h_p, h_q, h_g, h_y));

		signature >> pk_rs_d;
	}
	else if (h_pk_type == "ssh-rsa")
	{
		Integer h_e, h_n;
		hostkey >> h_e >> h_n;

		ipacket payload(m_host_payload.data(), m_host_payload.size());
		std::string key_exchange_alg, server_host_key_alg;

		payload.skip(16);
		payload >> key_exchange_alg >> server_host_key_alg;

		std::string alg = choose_protocol(server_host_key_alg, kServerHostKeyAlgorithms);

		if (alg == "ssh-rsa")
			h_key.reset(new RSASS<PKCS1v15, SHA1>::Verifier(h_n, h_e));
		else if (m_kx.m_pk_type == "rsa-sha2-256" and m_kx.m_pk_type == alg)
			h_key.reset(new RSASS<PKCS1v15, SHA256>::Verifier(h_n, h_e));
		else if (alg == "rsa-sha2-512" and m_kx.m_pk_type == alg)
			h_key.reset(new RSASS<PKCS1v15, SHA512>::Verifier(h_n, h_e));

		signature >> pk_rs_d;
	}
	else if (h_pk_type == "ecdsa-sha2-nistp256")
	{
		std::string identifier;
		blob Q;
		hostkey >> identifier >> Q;

		ECP::Point point;

		ECDSA<ECP, SHA256>::PublicKey pubKey;
		pubKey.AccessGroupParameters().Initialize(ASN1::secp256r1());

		pubKey.GetGroupParameters().GetCurve().DecodePoint(point, Q.data(), Q.size());
		pubKey.SetPublicElement(point);

		h_key.reset(new ECDSA<ECP, SHA256>::Verifier(pubKey));

		blob r, s;

		ipacket sig_rs;
		signature >> sig_rs;

		sig_rs >> r >> s;

		// convert to IEEE's P1363 format

		if (r.size() == 33)
			r.erase(r.begin(), r.begin() + 1);

		if (s.size() == 33)
			s.erase(s.begin(), s.begin() + 1);

		std::swap(r, pk_rs_d);
		pk_rs_d.insert(pk_rs_d.end(), s.begin(), s.end());
	}

	if (m_kx.m_pk_type == h_pk_type and h_key and h_key->VerifyMessage(m_H.data(), m_H.size(), pk_rs_d.data(), pk_rs_d.size()))
		out = msg_newkeys;
	else
		ec = error::make_error_code(error::host_key_verification_failed);

	derive_keys();
}

// --------------------------------------------------------------------

template <class HashAlgorithm>
class key_exchange_dh_group : public key_exchange_impl
{
  public:
	key_exchange_dh_group(key_exchange &kx, const Integer &p)
		: key_exchange_impl(kx)
	{
		m_p = p;
		m_q = (p - 1) / 2;
		m_g = 2;
	}

	virtual bool process(ipacket &in, opacket &out, boost::system::error_code &ec);
	virtual void calculate_hash(const std::string &host_version, ipacket &hostkey, CryptoPP::Integer &f);

	virtual void derive_keys()
	{
		do_derive_keys<HashAlgorithm>();
	}
};

template <class HashAlgorithm>
bool key_exchange_dh_group<HashAlgorithm>::process(ipacket &in, opacket &out, boost::system::error_code &ec)
{
	bool handled = true;

	switch ((message_type)in)
	{
		case msg_kexinit:
			do
			{
				m_x.Randomize(rng, m_g, m_q - 1);
				m_e = a_exp_b_mod_c(m_g, m_x, m_p);
			} while (m_e < 1 or m_e >= m_p - 1);

			out = msg_kex_dh_init;
			out << m_e;
			break;

		default:
			handled = key_exchange_impl::process(in, out, ec);
			break;
	}

	return handled;
}

template <class HashAlgorithm>
void key_exchange_dh_group<HashAlgorithm>::calculate_hash(const std::string &host_version, ipacket &hostkey, Integer &f)
{
	opacket hp;
	hp << kSSHVersionString << host_version << m_my_payload << m_host_payload << hostkey << m_e << f << m_K;

	m_H = hash<HashAlgorithm>().update(hp).final();
}

// --------------------------------------------------------------------

template <typename HashAlgorithm>
class key_exchange_dh_gex : public key_exchange_impl
{
  public:
	key_exchange_dh_gex(key_exchange &kx)
		: key_exchange_impl(kx)
	{
	}

	virtual bool process(ipacket &in, opacket &out, boost::system::error_code &ec);
	virtual void calculate_hash(const std::string &host_version, ipacket &hostkey, Integer &f);

	virtual void derive_keys()
	{
		do_derive_keys<HashAlgorithm>();
	}

	static const uint32_t kMinGroupSize = 1024,
						  kPreferredGroupSize = 2048,
						  kMaxGroupSize = 8192;
};

template <typename HashAlgorithm>
bool key_exchange_dh_gex<HashAlgorithm>::process(ipacket &in, opacket &out, boost::system::error_code &ec)
{
	bool handled = true;

	switch ((message_type)in)
	{
		case msg_kexinit:
			out = msg_kex_dh_gex_request;
			out << kMinGroupSize << kPreferredGroupSize << kMaxGroupSize;
			break;

		case msg_kex_dh_gex_group:
			in >> m_p >> m_g;
			m_q = (m_p - 1) / 2;

			do
			{
				m_x.Randomize(rng, m_g, m_q - 1);
				m_e = a_exp_b_mod_c(m_g, m_x, m_p);
			} while (m_e < 1 or m_e >= m_p - 1);

			out = msg_kex_dh_gex_init;
			out << m_e;
			break;

		default:
			handled = key_exchange_impl::process(in, out, ec);
			break;
	}

	return handled;
}

template <typename HashAlgorithm>
void key_exchange_dh_gex<HashAlgorithm>::calculate_hash(const std::string &host_version, ipacket &hostkey, Integer &f)
{
	opacket hp;

	hp << kSSHVersionString << host_version << m_my_payload << m_host_payload << hostkey
	   << kMinGroupSize << kPreferredGroupSize << kMaxGroupSize
	   << m_p << m_g << m_e << f << m_K;

	m_H = hash<HashAlgorithm>().update(hp).final();
}

// --------------------------------------------------------------------

std::string
	key_exchange::s_alg_kex = kKeyExchangeAlgorithms,
	key_exchange::s_alg_enc_s2c = kEncryptionAlgorithms,
	key_exchange::s_alg_enc_c2s = kEncryptionAlgorithms,
	key_exchange::s_alg_ver_s2c = kMacAlgorithms,
	key_exchange::s_alg_ver_c2s = kMacAlgorithms,
	key_exchange::s_alg_cmp_s2c = kCompressionAlgorithms,
	key_exchange::s_alg_cmp_c2s = kCompressionAlgorithms;

key_exchange::key_exchange(const std::string &host_version)
	: m_host_version(host_version)
{
}

key_exchange::key_exchange(const std::string &host_version, const blob &session_id)
	: m_host_version(host_version)
	, m_session_id(session_id)
{
}

key_exchange::~key_exchange()
{
	delete m_impl;
}

bool key_exchange::process(ipacket &in, opacket &out, boost::system::error_code &ec)
{
	bool handled = true;

	switch ((message_type)in)
	{
		case msg_kexinit:
			process_kexinit(in, out, ec);
			break;

		default:
			handled = m_impl ? m_impl->process(in, out, ec) : false;
	}

	return handled;
}

void key_exchange::set_algorithm(algorithm alg, direction dir, const std::string &preferred)
{
	switch (alg)
	{
		case algorithm::keyexchange:
			s_alg_kex = preferred;
			break;

		case algorithm::encryption:
			if (dir != direction::c2s)
				s_alg_enc_s2c = preferred;
			if (dir != direction::s2c)
				s_alg_enc_c2s = preferred;
			break;

		case algorithm::verification:
			if (dir != direction::c2s)
				s_alg_ver_s2c = preferred;
			if (dir != direction::s2c)
				s_alg_ver_c2s = preferred;
			break;

		case algorithm::compression:
			if (dir != direction::c2s)
				s_alg_cmp_s2c = preferred;
			if (dir != direction::s2c)
				s_alg_cmp_c2s = preferred;
			break;
	}
}

opacket key_exchange::init()
{
	// create the kexinit out message
	opacket out = {msg_kexinit};
	for (uint32_t i = 0; i < 16; ++i)
		out << rng.GenerateByte();

	out << s_alg_kex
		<< kServerHostKeyAlgorithms
		<< s_alg_enc_c2s
		<< s_alg_enc_s2c
		<< s_alg_ver_c2s
		<< s_alg_ver_s2c
		<< s_alg_cmp_c2s
		<< s_alg_cmp_s2c
		<< ""
		<< ""
		<< false
		<< uint32_t(0);

	m_my_payload = out;

	return out;
}

void key_exchange::process_kexinit(ipacket &in, opacket &out, boost::system::error_code &ec)
{
	m_host_payload = in;

	std::string key_exchange_alg;
	in.skip(16);
	in >> key_exchange_alg;

	key_exchange_alg = choose_protocol(key_exchange_alg, s_alg_kex);

	if (key_exchange_alg.empty())
		ec = error::make_error_code(error::protocol_version_not_supported);
	else
	{
		// diffie hellman group 1 and group 14 primes
		const unsigned char
			p2[] = {
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
				0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
				0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
				0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
				0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
				0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
				0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
				0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			p14[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD, 0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED, 0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D, 0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F, 0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D, 0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B, 0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F, 0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9, 0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10, 0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, p16[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD, 0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED, 0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D, 0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F, 0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D, 0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B, 0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F, 0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9, 0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10, 0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAA, 0xC4, 0x2D, 0xAD, 0x33, 0x17, 0x0D, 0x04, 0x50, 0x7A, 0x33, 0xA8, 0x55, 0x21, 0xAB, 0xDF, 0x1C, 0xBA, 0x64, 0xEC, 0xFB, 0x85, 0x04, 0x58, 0xDB, 0xEF, 0x0A, 0x8A, 0xEA, 0x71, 0x57, 0x5D, 0x06, 0x0C, 0x7D, 0xB3, 0x97, 0x0F, 0x85, 0xA6, 0xE1, 0xE4, 0xC7, 0xAB, 0xF5, 0xAE, 0x8C, 0xDB, 0x09, 0x33, 0xD7, 0x1E, 0x8C, 0x94, 0xE0, 0x4A, 0x25, 0x61, 0x9D, 0xCE, 0xE3, 0xD2, 0x26, 0x1A, 0xD2, 0xEE, 0x6B, 0xF1, 0x2F, 0xFA, 0x06, 0xD9, 0x8A, 0x08, 0x64, 0xD8, 0x76, 0x02, 0x73, 0x3E, 0xC8, 0x6A, 0x64, 0x52, 0x1F, 0x2B, 0x18, 0x17, 0x7B, 0x20, 0x0C, 0xBB, 0xE1, 0x17, 0x57, 0x7A, 0x61, 0x5D, 0x6C, 0x77, 0x09, 0x88, 0xC0, 0xBA, 0xD9, 0x46, 0xE2, 0x08, 0xE2, 0x4F, 0xA0, 0x74, 0xE5, 0xAB, 0x31, 0x43, 0xDB, 0x5B, 0xFC, 0xE0, 0xFD, 0x10, 0x8E, 0x4B, 0x82, 0xD1, 0x20, 0xA9, 0x21, 0x08, 0x01, 0x1A, 0x72, 0x3C, 0x12, 0xA7, 0x87, 0xE6, 0xD7, 0x88, 0x71, 0x9A, 0x10, 0xBD, 0xBA, 0x5B, 0x26, 0x99, 0xC3, 0x27, 0x18, 0x6A, 0xF4, 0xE2, 0x3C, 0x1A, 0x94, 0x68, 0x34, 0xB6, 0x15, 0x0B, 0xDA, 0x25, 0x83, 0xE9, 0xCA, 0x2A, 0xD4, 0x4C, 0xE8, 0xDB, 0xBB, 0xC2, 0xDB, 0x04, 0xDE, 0x8E, 0xF9, 0x2E, 0x8E, 0xFC, 0x14, 0x1F, 0xBE, 0xCA, 0xA6, 0x28, 0x7C, 0x59, 0x47, 0x4E, 0x6B, 0xC0, 0x5D, 0x99, 0xB2, 0x96, 0x4F, 0xA0, 0x90, 0xC3, 0xA2, 0x23, 0x3B, 0xA1, 0x86, 0x51, 0x5B, 0xE7, 0xED, 0x1F, 0x61, 0x29, 0x70, 0xCE, 0xE2, 0xD7, 0xAF, 0xB8, 0x1B, 0xDD, 0x76, 0x21, 0x70, 0x48, 0x1C, 0xD0, 0x06, 0x91, 0x27, 0xD5, 0xB0, 0x5A, 0xA9, 0x93, 0xB4, 0xEA, 0x98, 0x8D, 0x8F, 0xDD, 0xC1, 0x86, 0xFF, 0xB7, 0xDC, 0x90, 0xA6, 0xC0, 0x8F, 0x4D, 0xF4, 0x35, 0xC9, 0x34, 0x06, 0x31, 0x99, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, p18[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD, 0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED, 0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D, 0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F, 0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D, 0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B, 0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F, 0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9, 0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10, 0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAA, 0xC4, 0x2D, 0xAD, 0x33, 0x17, 0x0D, 0x04, 0x50, 0x7A, 0x33, 0xA8, 0x55, 0x21, 0xAB, 0xDF, 0x1C, 0xBA, 0x64, 0xEC, 0xFB, 0x85, 0x04, 0x58, 0xDB, 0xEF, 0x0A, 0x8A, 0xEA, 0x71, 0x57, 0x5D, 0x06, 0x0C, 0x7D, 0xB3, 0x97, 0x0F, 0x85, 0xA6, 0xE1, 0xE4, 0xC7, 0xAB, 0xF5, 0xAE, 0x8C, 0xDB, 0x09, 0x33, 0xD7, 0x1E, 0x8C, 0x94, 0xE0, 0x4A, 0x25, 0x61, 0x9D, 0xCE, 0xE3, 0xD2, 0x26, 0x1A, 0xD2, 0xEE, 0x6B, 0xF1, 0x2F, 0xFA, 0x06, 0xD9, 0x8A, 0x08, 0x64, 0xD8, 0x76, 0x02, 0x73, 0x3E, 0xC8, 0x6A, 0x64, 0x52, 0x1F, 0x2B, 0x18, 0x17, 0x7B, 0x20, 0x0C, 0xBB, 0xE1, 0x17, 0x57, 0x7A, 0x61, 0x5D, 0x6C, 0x77, 0x09, 0x88, 0xC0, 0xBA, 0xD9, 0x46, 0xE2, 0x08, 0xE2, 0x4F, 0xA0, 0x74, 0xE5, 0xAB, 0x31, 0x43, 0xDB, 0x5B, 0xFC, 0xE0, 0xFD, 0x10, 0x8E, 0x4B, 0x82, 0xD1, 0x20, 0xA9, 0x21, 0x08, 0x01, 0x1A, 0x72, 0x3C, 0x12, 0xA7, 0x87, 0xE6, 0xD7, 0x88, 0x71, 0x9A, 0x10, 0xBD, 0xBA, 0x5B, 0x26, 0x99, 0xC3, 0x27, 0x18, 0x6A, 0xF4, 0xE2, 0x3C, 0x1A, 0x94, 0x68, 0x34, 0xB6, 0x15, 0x0B, 0xDA, 0x25, 0x83, 0xE9, 0xCA, 0x2A, 0xD4, 0x4C, 0xE8, 0xDB, 0xBB, 0xC2, 0xDB, 0x04, 0xDE, 0x8E, 0xF9, 0x2E, 0x8E, 0xFC, 0x14, 0x1F, 0xBE, 0xCA, 0xA6, 0x28, 0x7C, 0x59, 0x47, 0x4E, 0x6B, 0xC0, 0x5D, 0x99, 0xB2, 0x96, 0x4F, 0xA0, 0x90, 0xC3, 0xA2, 0x23, 0x3B, 0xA1, 0x86, 0x51, 0x5B, 0xE7, 0xED, 0x1F, 0x61, 0x29, 0x70, 0xCE, 0xE2, 0xD7, 0xAF, 0xB8, 0x1B, 0xDD, 0x76, 0x21, 0x70, 0x48, 0x1C, 0xD0, 0x06, 0x91, 0x27, 0xD5, 0xB0, 0x5A, 0xA9, 0x93, 0xB4, 0xEA, 0x98, 0x8D, 0x8F, 0xDD, 0xC1, 0x86, 0xFF, 0xB7, 0xDC, 0x90, 0xA6, 0xC0, 0x8F, 0x4D, 0xF4, 0x35, 0xC9, 0x34, 0x02, 0x84, 0x92, 0x36, 0xC3, 0xFA, 0xB4, 0xD2, 0x7C, 0x70, 0x26, 0xC1, 0xD4, 0xDC, 0xB2, 0x60, 0x26, 0x46, 0xDE, 0xC9, 0x75, 0x1E, 0x76, 0x3D, 0xBA, 0x37, 0xBD, 0xF8, 0xFF, 0x94, 0x06, 0xAD, 0x9E, 0x53, 0x0E, 0xE5, 0xDB, 0x38, 0x2F, 0x41, 0x30, 0x01, 0xAE, 0xB0, 0x6A, 0x53, 0xED, 0x90, 0x27, 0xD8, 0x31, 0x17, 0x97, 0x27, 0xB0, 0x86, 0x5A, 0x89, 0x18, 0xDA, 0x3E, 0xDB, 0xEB, 0xCF, 0x9B, 0x14, 0xED, 0x44, 0xCE, 0x6C, 0xBA, 0xCE, 0xD4, 0xBB, 0x1B, 0xDB, 0x7F, 0x14, 0x47, 0xE6, 0xCC, 0x25, 0x4B, 0x33, 0x20, 0x51, 0x51, 0x2B, 0xD7, 0xAF, 0x42, 0x6F, 0xB8, 0xF4, 0x01, 0x37, 0x8C, 0xD2, 0xBF, 0x59, 0x83, 0xCA, 0x01, 0xC6, 0x4B, 0x92, 0xEC, 0xF0, 0x32, 0xEA, 0x15, 0xD1, 0x72, 0x1D, 0x03, 0xF4, 0x82, 0xD7, 0xCE, 0x6E, 0x74, 0xFE, 0xF6, 0xD5, 0x5E, 0x70, 0x2F, 0x46, 0x98, 0x0C, 0x82, 0xB5, 0xA8, 0x40, 0x31, 0x90, 0x0B, 0x1C, 0x9E, 0x59, 0xE7, 0xC9, 0x7F, 0xBE, 0xC7, 0xE8, 0xF3, 0x23, 0xA9, 0x7A, 0x7E, 0x36, 0xCC, 0x88, 0xBE, 0x0F, 0x1D, 0x45, 0xB7, 0xFF, 0x58, 0x5A, 0xC5, 0x4B, 0xD4, 0x07, 0xB2, 0x2B, 0x41, 0x54, 0xAA, 0xCC, 0x8F, 0x6D, 0x7E, 0xBF, 0x48, 0xE1, 0xD8, 0x14, 0xCC, 0x5E, 0xD2, 0x0F, 0x80, 0x37, 0xE0, 0xA7, 0x97, 0x15, 0xEE, 0xF2, 0x9B, 0xE3, 0x28, 0x06, 0xA1, 0xD5, 0x8B, 0xB7, 0xC5, 0xDA, 0x76, 0xF5, 0x50, 0xAA, 0x3D, 0x8A, 0x1F, 0xBF, 0xF0, 0xEB, 0x19, 0xCC, 0xB1, 0xA3, 0x13, 0xD5, 0x5C, 0xDA, 0x56, 0xC9, 0xEC, 0x2E, 0xF2, 0x96, 0x32, 0x38, 0x7F, 0xE8, 0xD7, 0x6E, 0x3C, 0x04, 0x68, 0x04, 0x3E, 0x8F, 0x66, 0x3F, 0x48, 0x60, 0xEE, 0x12, 0xBF, 0x2D, 0x5B, 0x0B, 0x74, 0x74, 0xD6, 0xE6, 0x94, 0xF9, 0x1E, 0x6D, 0xBE, 0x11, 0x59, 0x74, 0xA3, 0x92, 0x6F, 0x12, 0xFE, 0xE5, 0xE4, 0x38, 0x77, 0x7C, 0xB6, 0xA9, 0x32, 0xDF, 0x8C, 0xD8, 0xBE, 0xC4, 0xD0, 0x73, 0xB9, 0x31, 0xBA, 0x3B, 0xC8, 0x32, 0xB6, 0x8D, 0x9D, 0xD3, 0x00, 0x74, 0x1F, 0xA7, 0xBF, 0x8A, 0xFC, 0x47, 0xED, 0x25, 0x76, 0xF6, 0x93, 0x6B, 0xA4, 0x24, 0x66, 0x3A, 0xAB, 0x63, 0x9C, 0x5A, 0xE4, 0xF5, 0x68, 0x34, 0x23, 0xB4, 0x74, 0x2B, 0xF1, 0xC9, 0x78, 0x23, 0x8F, 0x16, 0xCB, 0xE3, 0x9D, 0x65, 0x2D, 0xE3, 0xFD, 0xB8, 0xBE, 0xFC, 0x84, 0x8A, 0xD9, 0x22, 0x22, 0x2E, 0x04, 0xA4, 0x03, 0x7C, 0x07, 0x13, 0xEB, 0x57, 0xA8, 0x1A, 0x23, 0xF0, 0xC7, 0x34, 0x73, 0xFC, 0x64, 0x6C, 0xEA, 0x30, 0x6B, 0x4B, 0xCB, 0xC8, 0x86, 0x2F, 0x83, 0x85, 0xDD, 0xFA, 0x9D, 0x4B, 0x7F, 0xA2, 0xC0, 0x87, 0xE8, 0x79, 0x68, 0x33, 0x03, 0xED, 0x5B, 0xDD, 0x3A, 0x06, 0x2B, 0x3C, 0xF5, 0xB3, 0xA2, 0x78, 0xA6, 0x6D, 0x2A, 0x13, 0xF8, 0x3F, 0x44, 0xF8, 0x2D, 0xDF, 0x31, 0x0E, 0xE0, 0x74, 0xAB, 0x6A, 0x36, 0x45, 0x97, 0xE8, 0x99, 0xA0, 0x25, 0x5D, 0xC1, 0x64, 0xF3, 0x1C, 0xC5, 0x08, 0x46, 0x85, 0x1D, 0xF9, 0xAB, 0x48, 0x19, 0x5D, 0xED, 0x7E, 0xA1, 0xB1, 0xD5, 0x10, 0xBD, 0x7E, 0xE7, 0x4D, 0x73, 0xFA, 0xF3, 0x6B, 0xC3, 0x1E, 0xCF, 0xA2, 0x68, 0x35, 0x90, 0x46, 0xF4, 0xEB, 0x87, 0x9F, 0x92, 0x40, 0x09, 0x43, 0x8B, 0x48, 0x1C, 0x6C, 0xD7, 0x88, 0x9A, 0x00, 0x2E, 0xD5, 0xEE, 0x38, 0x2B, 0xC9, 0x19, 0x0D, 0xA6, 0xFC, 0x02, 0x6E, 0x47, 0x95, 0x58, 0xE4, 0x47, 0x56, 0x77, 0xE9, 0xAA, 0x9E, 0x30, 0x50, 0xE2, 0x76, 0x56, 0x94, 0xDF, 0xC8, 0x1F, 0x56, 0xE8, 0x80, 0xB9, 0x6E, 0x71, 0x60, 0xC9, 0x80, 0xDD, 0x98, 0xED, 0xD3, 0xDF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

		if (key_exchange_alg == "diffie-hellman-group1-sha1")
			m_impl = new key_exchange_dh_group<SHA1>(*this, Integer(p2, sizeof(p2)));
		else if (key_exchange_alg == "diffie-hellman-group14-sha1")
			m_impl = new key_exchange_dh_group<SHA1>(*this, Integer(p14, sizeof(p14)));
		else if (key_exchange_alg == "diffie-hellman-group14-sha256")
			m_impl = new key_exchange_dh_group<SHA256>(*this, Integer(p14, sizeof(p14)));
		else if (key_exchange_alg == "diffie-hellman-group16-sha512")
			m_impl = new key_exchange_dh_group<SHA512>(*this, Integer(p16, sizeof(p16)));
		else if (key_exchange_alg == "diffie-hellman-group18-sha512")
			m_impl = new key_exchange_dh_group<SHA512>(*this, Integer(p18, sizeof(p18)));
		else if (key_exchange_alg == "diffie-hellman-group-exchange-sha1")
			m_impl = new key_exchange_dh_gex<SHA1>(*this);
		else if (key_exchange_alg == "diffie-hellman-group-exchange-sha256")
			m_impl = new key_exchange_dh_gex<SHA256>(*this);
		else
			assert(false);

		m_impl->process(in, out, ec);
	}
}

const uint8_t *key_exchange::key(key_enum k) const
{
	return m_impl->m_keys[k].data();
}

ipacket key_exchange::host_payload() const
{
	return ipacket(m_impl->m_host_payload.data(), m_impl->m_host_payload.size());
}

std::string key_exchange::get_encryption_protocol(direction dir) const
{
	ipacket payload = host_payload();

	std::string key_exchange_alg, server_host_key_alg, encryption_alg_c2s, encryption_alg_s2c,
		MAC_alg_c2s, MAC_alg_s2c, compression_alg_c2s, compression_alg_s2c;

	payload.skip(16);
	payload >> key_exchange_alg >> server_host_key_alg >> encryption_alg_c2s >> encryption_alg_s2c >> MAC_alg_c2s >> MAC_alg_s2c >> compression_alg_c2s >> compression_alg_s2c;

	return dir == direction::c2s ? choose_protocol(encryption_alg_c2s, s_alg_enc_c2s) : choose_protocol(encryption_alg_s2c, s_alg_enc_c2s);
}

std::string key_exchange::get_verification_protocol(direction dir) const
{
	ipacket payload = host_payload();

	std::string key_exchange_alg, server_host_key_alg, encryption_alg_c2s, encryption_alg_s2c,
		MAC_alg_c2s, MAC_alg_s2c, compression_alg_c2s, compression_alg_s2c;

	payload.skip(16);
	payload >> key_exchange_alg >> server_host_key_alg >> encryption_alg_c2s >> encryption_alg_s2c >> MAC_alg_c2s >> MAC_alg_s2c >> compression_alg_c2s >> compression_alg_s2c;

	return dir == direction::c2s ? choose_protocol(MAC_alg_c2s, s_alg_ver_c2s) : choose_protocol(MAC_alg_s2c, s_alg_ver_s2c);
}

std::string key_exchange::get_compression_protocol(direction dir) const
{
	ipacket payload = host_payload();

	std::string key_exchange_alg, server_host_key_alg, encryption_alg_c2s, encryption_alg_s2c,
		MAC_alg_c2s, MAC_alg_s2c, compression_alg_c2s, compression_alg_s2c;

	payload.skip(16);
	payload >> key_exchange_alg >> server_host_key_alg >> encryption_alg_c2s >> encryption_alg_s2c >> MAC_alg_c2s >> MAC_alg_s2c >> compression_alg_c2s >> compression_alg_s2c;

	return dir ==
				   direction::c2s
			   ? choose_protocol(compression_alg_c2s, s_alg_cmp_c2s)
			   : choose_protocol(compression_alg_s2c, s_alg_cmp_s2c);
}

} // namespace pinch
