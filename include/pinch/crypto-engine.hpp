#pragma once

#include <pinch/packet.hpp>
#include <pinch/key_exchange.hpp>

namespace pinch
{

extern const std::string
	kKeyExchangeAlgorithms,
	kServerHostKeyAlgorithms,
	kEncryptionAlgorithms,
	kMacAlgorithms,
	kCompressionAlgorithms;

std::string choose_protocol(const std::string &server, const std::string &client);

// --------------------------------------------------------------------

class crypto_engine
{
  public:
	crypto_engine(const crypto_engine&) = delete;
	crypto_engine& operator=(const crypto_engine&) = delete;


	// configure before connecting
	static void set_algorithm(algorithm alg, direction dir, const std::string &preferred);

	crypto_engine();

	void newkeys(key_exchange& kex, bool authenticated);
	void enable_compression();
	void reset();

	std::size_t get_iblocksize() const;
	std::size_t get_oblocksize() const;

	std::unique_ptr<ipacket> get_next_packet(boost::asio::streambuf& buffer, boost::system::error_code& ec);
	std::unique_ptr<boost::asio::streambuf> get_next_request(opacket&& p);

	uint32_t get_next_out_seq_nr() const		{ return m_out_seq_nr; }

  private:

	blob get_next_block(boost::asio::streambuf& buffer, bool empty);

	std::size_t m_iblocksize = 8, m_oblocksize = 8;
	uint32_t m_in_seq_nr = 0, m_out_seq_nr = 0;

	std::string m_alg_kex,
		m_alg_enc_c2s = kEncryptionAlgorithms, m_alg_ver_c2s = kMacAlgorithms, m_alg_cmp_c2s = kCompressionAlgorithms,
		m_alg_enc_s2c = kEncryptionAlgorithms, m_alg_ver_s2c = kMacAlgorithms, m_alg_cmp_s2c = kCompressionAlgorithms;

	std::unique_ptr<CryptoPP::StreamTransformation> m_decryptor;
	std::unique_ptr<CryptoPP::StreamTransformation> m_encryptor;
	std::unique_ptr<CryptoPP::MessageAuthenticationCode> m_signer;
	std::unique_ptr<CryptoPP::MessageAuthenticationCode> m_verifier;

	std::unique_ptr<compression_helper> m_compressor;
	std::unique_ptr<compression_helper> m_decompressor;
	bool m_delay_compressor, m_delay_decompressor;

	std::unique_ptr<ipacket> m_packet;
};

}
