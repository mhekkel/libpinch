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
struct key_exchange_impl;

class key_exchange
{
  public:
	key_exchange(const std::string& host_version);
	key_exchange(const std::string& host_version, const std::vector<uint8_t>& session_id);
	~key_exchange();

	key_exchange(const key_exchange&) = delete;
	key_exchange& operator=(const key_exchange&) = delete;

	opacket init();

	bool process(ipacket& in, opacket& out, boost::system::error_code& ec);

	enum key_enum { A, B, C, D, E, F };
	const uint8_t *key(key_enum k) const;
	// const uint8_t *key(key_enum k) const { return m_keys[k].data(); }

	const std::vector<uint8_t>& session_id() const { return m_session_id; }

	std::string get_encryption_protocol(direction dir) const;
	std::string get_verification_protocol(direction dir) const;
	std::string get_compression_protocol(direction dir) const;

	ipacket host_payload() const;

  protected:

	friend struct key_exchange_impl;

	void process_kexinit(ipacket& in, opacket& out, boost::system::error_code& ec);

	key_exchange_impl* m_impl = nullptr;

	std::string m_host_version;
	std::vector<uint8_t> m_session_id;
	std::vector<uint8_t> m_host_payload, m_my_payload;
	bool m_first_kex_packet_follows;
 	verify_host_key_func cb_verify_host_key;
 };

} // namespace assh
