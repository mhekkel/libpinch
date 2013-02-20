//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

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

	static key_exchange*	create(ipacket& in);

	virtual opacket			process_kexinit() = 0;
	virtual opacket			process_kexdhreply(ipacket& in,
								const std::string& host_version, std::vector<uint8>& session_id,
								const std::vector<uint8>& my_payload, const std::vector<uint8>& host_payload,
								boost::system::error_code& ec);

	virtual opacket			process_kexdhgexgroup(ipacket& in, boost::system::error_code& ec);
	virtual opacket			process_kexdhgexreply(ipacket& in, boost::system::error_code& ec);

	CryptoPP::StreamTransformation*			decryptor();
	CryptoPP::StreamTransformation*			encryptor();
	CryptoPP::MessageAuthenticationCode*	signer();
	CryptoPP::MessageAuthenticationCode*	verifier();
  	
  protected:

							key_exchange();

	virtual void			calculate_hash(ipacket& hostkey, CryptoPP::Integer& f, const std::string& host_version,
								const std::vector<uint8>& my_payload, const std::vector<uint8>& host_payload) = 0;

	CryptoPP::Integer		m_x, m_e, m_K;
	std::string				m_encryption_alg_c2s, m_encryption_alg_s2c,
							m_MAC_alg_c2s, m_MAC_alg_s2c,
							m_compression_alg_c2s, m_compression_alg_s2c,
							m_lang_c2s, m_lang_s2c;
	std::vector<uint8>		m_H, m_keys[6];
};

}
