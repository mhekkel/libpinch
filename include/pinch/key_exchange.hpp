//        Copyright Maarten L. Hekkelman 2013-2021
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include <functional>

#include <pinch/packet.hpp>
#include <pinch/pinch.hpp>

namespace pinch
{

// --------------------------------------------------------------------
// The defaults for our protocols

extern const std::string
	kKeyExchangeAlgorithms,
	kServerHostKeyAlgorithms, kEncryptionAlgorithms, kMacAlgorithms, kCompressionAlgorithms;

// --------------------------------------------------------------------

std::string choose_protocol(const std::string &server, const std::string &client);

// --------------------------------------------------------------------

struct key_exchange_impl;

class key_exchange
{
  public:
	// configure before connecting
	static void set_algorithm(algorithm alg, direction dir, const std::string &preferred);

	key_exchange(const std::string &host_version);
	key_exchange(const std::string &host_version, const blob &session_id);
	~key_exchange();

	key_exchange(const key_exchange &) = delete;
	key_exchange &operator=(const key_exchange &) = delete;

	opacket init();

	bool process(ipacket &in, opacket &out, boost::system::error_code &ec);

	enum key_enum
	{
		A,
		B,
		C,
		D,
		E,
		F
	};
	const uint8_t *key(key_enum k) const;
	// const uint8_t *key(key_enum k) const { return m_keys[k].data(); }

	const blob &session_id() const { return m_session_id; }

	std::string get_encryption_protocol(direction dir) const;
	std::string get_verification_protocol(direction dir) const;
	std::string get_compression_protocol(direction dir) const;

	ipacket host_payload() const;

	const std::string& get_host_key_pk_type() const	{ return m_pk_type; }
	const blob& get_host_key() const { return m_host_key; }

  protected:
	friend struct key_exchange_impl;

	void process_kexinit(ipacket &in, opacket &out, boost::system::error_code &ec);

	key_exchange_impl *m_impl = nullptr;

	std::string m_host_version;
	blob m_session_id;
	blob m_host_payload, m_my_payload;
	bool m_first_kex_packet_follows;
	
	std::string m_pk_type;
	blob m_host_key;

	// --------------------------------------------------------------------

	static std::string
		s_alg_kex,
		s_alg_enc_s2c, s_alg_enc_c2s, s_alg_ver_s2c, s_alg_ver_c2s, s_alg_cmp_s2c, s_alg_cmp_c2s;
};

} // namespace pinch
