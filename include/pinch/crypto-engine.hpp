//        Copyright Maarten L. Hekkelman 2013-2021
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include <boost/asio/streambuf.hpp>

#include <pinch/key_exchange.hpp>
#include <pinch/packet.hpp>

namespace pinch
{

// --------------------------------------------------------------------

class crypto_engine
{
  public:
	crypto_engine(const crypto_engine &) = delete;
	crypto_engine &operator=(const crypto_engine &) = delete;

	crypto_engine();

	std::string get_connection_parameters(direction dir) const;
	std::string get_key_exchange_algorithm() const;

	void newkeys(key_exchange &kex, bool authenticated);
	void enable_compression();
	void reset();

	std::size_t get_iblocksize() const;
	std::size_t get_oblocksize() const;

	std::unique_ptr<ipacket> get_next_packet(boost::asio::streambuf &buffer, boost::system::error_code &ec);
	std::unique_ptr<boost::asio::streambuf> get_next_request(opacket &&p);

  private:
	blob get_next_block(boost::asio::streambuf &buffer, bool empty);

	std::size_t m_iblocksize = 8, m_oblocksize = 8;
	uint32_t m_in_seq_nr = 0, m_out_seq_nr = 0;

	std::string m_alg_kex,
		m_alg_enc_c2s, m_alg_ver_c2s, m_alg_cmp_c2s,
		m_alg_enc_s2c, m_alg_ver_s2c, m_alg_cmp_s2c;

	std::unique_ptr<CryptoPP::StreamTransformation> m_decryptor;
	std::unique_ptr<CryptoPP::StreamTransformation> m_encryptor;
	std::unique_ptr<CryptoPP::MessageAuthenticationCode> m_signer;
	std::unique_ptr<CryptoPP::MessageAuthenticationCode> m_verifier;

	std::unique_ptr<compression_helper> m_compressor;
	std::unique_ptr<compression_helper> m_decompressor;
	bool m_delay_compressor, m_delay_decompressor;

	std::unique_ptr<ipacket> m_packet;

	std::mutex m_in_mutex, m_out_mutex;
};

} // namespace pinch
