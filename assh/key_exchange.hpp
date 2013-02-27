//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include <boost/function.hpp>

#include <assh/config.hpp>
#include <assh/packet.hpp>

namespace assh
{

extern const std::string
	kKeyExchangeAlgorithms, kServerHostKeyAlgorithms,
	kEncryptionAlgorithms, kMacAlgorithms,
	kUseCompressionAlgorithms, kDontUseCompressionAlgorithms;

std::string choose_protocol(const std::string& server, const std::string& client);

class key_exchange
{
  public:

	static key_exchange*	create(ipacket& in, const std::string& host_version, std::vector<uint8>& session_id,
								const std::vector<uint8>& my_payload);

	virtual bool			process(ipacket& in, opacket& out, boost::system::error_code& ec);

	boost::function<bool(const std::string&,const std::vector<uint8>&)>
							cb_verify_host_key;

	CryptoPP::StreamTransformation*			decryptor();
	CryptoPP::StreamTransformation*			encryptor();
	CryptoPP::MessageAuthenticationCode*	signer();
	CryptoPP::MessageAuthenticationCode*	verifier();
  	
  protected:

							key_exchange(const std::string& host_version, std::vector<uint8>& session_id,
								const std::vector<uint8>& my_payload, const std::vector<uint8>& host_payload);

	void					init(ipacket& in);
	void					process_kex_dh_reply(ipacket& in, opacket& out, boost::system::error_code& ec);
	virtual void			calculate_hash(ipacket& hostkey, CryptoPP::Integer& f) = 0;

	template<typename HashAlgorithm>
	void					derive_keys();

	virtual void			derive_keys_with_hash();

	std::vector<uint8>&		m_session_id;
	std::string				m_host_version;
	std::vector<uint8>		m_host_payload, m_my_payload;
	CryptoPP::Integer		m_x, m_e, m_K, m_p, m_q, m_g;
	std::string				m_encryption_alg_c2s, m_encryption_alg_s2c,
							m_MAC_alg_c2s, m_MAC_alg_s2c,
							m_compression_alg_c2s, m_compression_alg_s2c,
							m_lang_c2s, m_lang_s2c;
	bool					m_first_kex_packet_follows;
	std::vector<uint8>		m_H, m_keys[6];
};

}
