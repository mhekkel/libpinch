//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include <assh/packet.hpp>

namespace assh
{

class key_exchange
{
  public:

	static key_exchange*	create(ipacket& in, const std::string& host_version,
								const std::vector<uint8>& my_payload);

	virtual opacket			process_kexinit() = 0;
	virtual opacket			process_kexdhreply(ipacket& in, boost::system::error_code& ec);
	virtual opacket			process_kexdhgexgroup(ipacket& in, boost::system::error_code& ec);
	virtual opacket			process_kexdhgexreply(ipacket& in, boost::system::error_code& ec);

	std::vector<uint8>		H() const		{ return m_H; }

	CryptoPP::StreamTransformation*			decryptor();
	CryptoPP::StreamTransformation*			encryptor();
	CryptoPP::MessageAuthenticationCode*	signer();
	CryptoPP::MessageAuthenticationCode*	verifier();
  	
  protected:

							key_exchange(ipacket& in, const std::string& host_version,
								const std::vector<uint8>& my_payload,
								const std::vector<uint8>& host_payload);

	virtual void			calculate_hash(ipacket& hostkey, CryptoPP::Integer& f) = 0;

	CryptoPP::Integer		m_x, m_e, m_K;
	std::string				m_host_version;
	std::vector<uint8>		m_my_payload, m_host_payload, m_session_id;
	std::string				m_kex_alg, m_server_host_key_alg,
							m_encryption_alg_c2s, m_encryption_alg_s2c,
							m_MAC_alg_c2s, m_MAC_alg_s2c,
							m_compression_alg_c2s, m_compression_alg_s2c,
							m_lang_c2s, m_lang_s2c;
	std::vector<uint8>		m_H, m_keys[6];
};

}
