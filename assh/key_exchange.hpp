//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include <functional>

#include <assh/config.hpp>
#include <assh/packet.hpp>

namespace assh
{

using verify_host_key_func = std::function<bool(const std::string&, const std::vector<uint8_t>&)>;

class key_exchange
{
  public:
	virtual ~key_exchange() = default;

	static key_exchange* init(ipacket& in, opacket& out, const std::string& host_version, const std::vector<uint8_t>& session_id = {});
	virtual bool process(ipacket& in, opacket& out, boost::system::error_code& ec);

	enum key_enum { A, B, C, D, E, F };
	const uint8_t *key(key_enum k) const { return &m_keys[k][0]; }

	const std::vector<uint8_t>& session_id() const { return m_session_id; }

	std::string get_encryption_protocol(direction dir) const;
	std::string get_verification_protocol(direction dir) const;
	std::string get_compression_protocol(direction dir) const;

  protected:
	key_exchange(const std::string& host_version, const std::vector<uint8_t>& session_id,
				 const std::vector<uint8_t>& my_payload, const std::vector<uint8_t>& host_payload);

	void process_kex_dh_reply(ipacket& in, opacket& out, boost::system::error_code& ec);
	virtual void calculate_hash(ipacket& hostkey, CryptoPP::Integer& f) = 0;

	template <typename HashAlgorithm>
	void derive_keys();

	virtual void derive_keys_with_hash();

	std::string m_host_version;
	std::vector<uint8_t> m_host_payload, m_my_payload;
	std::vector<uint8_t> m_session_id;
	CryptoPP::Integer m_x, m_e, m_K, m_p, m_q, m_g;
	bool m_first_kex_packet_follows;
	std::vector<uint8_t> m_H, m_keys[6];
 	verify_host_key_func cb_verify_host_key;
 };

} // namespace assh
