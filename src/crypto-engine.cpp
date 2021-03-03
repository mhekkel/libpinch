#include <pinch/pinch.hpp>
#include <pinch/crypto-engine.hpp>
#include <pinch/error.hpp>

#include <boost/algorithm/string.hpp>
#include <boost/iostreams/filtering_stream.hpp>

#include <cryptopp/cryptlib.h>
#include <cryptopp/gfpcrypt.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/aes.h>
#include <cryptopp/des.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/factory.h>
#include <cryptopp/modes.h>

namespace ba = boost::algorithm;
namespace io = boost::iostreams;

// --------------------------------------------------------------------

namespace pinch
{

const std::string
	kKeyExchangeAlgorithms("diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256"),
	kServerHostKeyAlgorithms("ecdsa-sha2-nistp256" /* ",rsa-sha2-512,rsa-sha2-256" */",ssh-rsa"),
	kEncryptionAlgorithms("aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,aes192-cbc,aes256-cbc,3des-cbc"),
	kMacAlgorithms("hmac-sha2-512,hmac-sha2-256"),
	kCompressionAlgorithms("zlib@openssh.com,zlib,none");

std::string choose_protocol(const std::string &server, const std::string &client)
{
	std::string result;
	bool found = false;

#warning "dit kan beter, zonder boost"

	typedef ba::split_iterator<std::string::const_iterator> split_iter_type;
	split_iter_type c = ba::make_split_iterator(client, ba::first_finder(",", ba::is_equal()));
	split_iter_type s = ba::make_split_iterator(server, ba::first_finder(",", ba::is_equal()));

	for (split_iter_type ci = c; not found and ci != split_iter_type(); ++ci)
	{
		for (split_iter_type si = s; not found and si != split_iter_type(); ++si)
		{
			if (*ci == *si)
			{
				result = boost::copy_range<std::string>(*ci);
				found = true;
			}
		}
	}

	return result;
}

// --------------------------------------------------------------------

struct packet_encryptor
{
	typedef char char_type;
	struct category : io::multichar_output_filter_tag, io::flushable_tag
	{
	};

	packet_encryptor(CryptoPP::StreamTransformation &cipher,
						CryptoPP::MessageAuthenticationCode &signer, uint32_t blocksize, uint32_t seq_nr)
		: m_cipher(cipher), m_signer(signer), m_blocksize(blocksize), m_flushed(false)
	{
		for (int i = 3; i >= 0; --i)
		{
			uint8_t ch = static_cast<uint8_t>(seq_nr >> (i * 8));
			m_signer.Update(&ch, 1);
		}

		m_block.reserve(m_blocksize);
	}

	template <typename Sink>
	std::streamsize write(Sink &sink, const char *s, std::streamsize n)
	{
		std::streamsize result = 0;

		for (std::streamsize o = 0; o < n; o += m_blocksize)
		{
			size_t k = n;
			if (k > m_blocksize - m_block.size())
				k = m_blocksize - m_block.size();

			const uint8_t *sp = reinterpret_cast<const uint8_t *>(s);

			m_signer.Update(sp, static_cast<size_t>(k));
			m_block.insert(m_block.end(), sp, sp + k);

			result += k;
			s += k;

			if (m_block.size() == m_blocksize)
			{
				blob block(m_blocksize);
				m_cipher.ProcessData(block.data(), m_block.data(), m_blocksize);

				for (uint32_t i = 0; i < m_blocksize; ++i)
					io::put(sink, block[i]);

				m_block.clear();
			}
		}

		return result;
	}

	template <typename Sink>
	bool flush(Sink &sink)
	{
		if (not m_flushed)
		{
			assert(m_block.size() == 0);

			blob digest(m_signer.DigestSize());
			m_signer.Final(digest.data());
			for (size_t i = 0; i < digest.size(); ++i)
				io::put(sink, digest[i]);

			m_flushed = true;
		}

		return true;
	}

	CryptoPP::StreamTransformation &m_cipher;
	CryptoPP::MessageAuthenticationCode &m_signer;
	blob m_block;
	uint32_t m_blocksize;
	bool m_flushed;
};

// --------------------------------------------------------------------

crypto_engine::crypto_engine()
{
}

void crypto_engine::newkeys(key_exchange& kex, bool authenticated)
{
	ipacket payload = kex.host_payload();

	std::string key_exchange_alg, server_host_key_alg, encryption_alg_c2s, encryption_alg_s2c,
		MAC_alg_c2s, MAC_alg_s2c, compression_alg_c2s, compression_alg_s2c;

	payload.skip(16);
	payload >> key_exchange_alg >> server_host_key_alg >> encryption_alg_c2s >> encryption_alg_s2c >> MAC_alg_c2s >> MAC_alg_s2c >> compression_alg_c2s >> compression_alg_s2c;

	// Client to server encryption
	std::string protocol = choose_protocol(encryption_alg_c2s, m_alg_enc_c2s);

	const uint8_t *key = kex.key(key_exchange::C);
	const uint8_t *iv = kex.key(key_exchange::A);

	if (protocol == "3des-cbc")
		m_encryptor.reset(new CryptoPP::CBC_Mode<CryptoPP::DES_EDE3>::Encryption(key, 24, iv));
	else if (protocol == "aes128-cbc")
		m_encryptor.reset(new CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption(key, 16, iv));
	else if (protocol == "aes192-cbc")
		m_encryptor.reset(new CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption(key, 24, iv));
	else if (protocol == "aes256-cbc")
		m_encryptor.reset(new CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption(key, 32, iv));
	else if (protocol == "aes128-ctr")
		m_encryptor.reset(new CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption(key, 16, iv));
	else if (protocol == "aes192-ctr")
		m_encryptor.reset(new CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption(key, 24, iv));
	else if (protocol == "aes256-ctr")
		m_encryptor.reset(new CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption(key, 32, iv));

	// Server to client encryption
	protocol = choose_protocol(encryption_alg_s2c, m_alg_enc_s2c);

	key = kex.key(key_exchange::D);
	iv = kex.key(key_exchange::B);

	if (protocol == "3des-cbc")
		m_decryptor.reset(new CryptoPP::CBC_Mode<CryptoPP::DES_EDE3>::Decryption(key, 24, iv));
	else if (protocol == "aes128-cbc")
		m_decryptor.reset(new CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption(key, 16, iv));
	else if (protocol == "aes192-cbc")
		m_decryptor.reset(new CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption(key, 24, iv));
	else if (protocol == "aes256-cbc")
		m_decryptor.reset(new CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption(key, 32, iv));
	else if (protocol == "aes128-ctr")
		m_decryptor.reset(new CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption(key, 16, iv));
	else if (protocol == "aes192-ctr")
		m_decryptor.reset(new CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption(key, 24, iv));
	else if (protocol == "aes256-ctr")
		m_decryptor.reset(new CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption(key, 32, iv));

	// Client To Server verification
	protocol = choose_protocol(MAC_alg_c2s, m_alg_ver_c2s);
	iv = kex.key(key_exchange::E);

	if (protocol == "hmac-sha2-512")
		m_signer.reset(new CryptoPP::HMAC<CryptoPP::SHA512>(iv, 64));
	else if (protocol == "hmac-sha2-256")
		m_signer.reset(new CryptoPP::HMAC<CryptoPP::SHA256>(iv, 32));
	else if (protocol == "hmac-sha1")
		m_signer.reset(new CryptoPP::HMAC<CryptoPP::SHA1>(iv, 20));
	else
		assert(false);

	// Server to Client verification

	protocol = choose_protocol(MAC_alg_s2c, m_alg_ver_s2c);
	iv = kex.key(key_exchange::F);

	if (protocol == "hmac-sha2-512")
		m_verifier.reset(new CryptoPP::HMAC<CryptoPP::SHA512>(iv, 64));
	else if (protocol == "hmac-sha2-256")
		m_verifier.reset(new CryptoPP::HMAC<CryptoPP::SHA256>(iv, 32));
	else if (protocol == "hmac-sha1")
		m_verifier.reset(new CryptoPP::HMAC<CryptoPP::SHA1>(iv, 20));
	else
		assert(false);

	// Client to Server compression
	protocol = choose_protocol(compression_alg_c2s, m_alg_cmp_c2s);
	if ((not m_compressor and protocol == "zlib") or (authenticated and protocol == "zlib@openssh.com"))
		m_compressor.reset(new compression_helper(true));
	else if (protocol == "zlib@openssh.com")
		m_delay_compressor = true;

	// Server to Client compression
	protocol = choose_protocol(compression_alg_s2c, m_alg_cmp_s2c);
	if ((not m_decompressor and protocol == "zlib") or (authenticated and protocol == "zlib@openssh.com"))
		m_decompressor.reset(new compression_helper(false));
	else if (protocol == "zlib@openssh.com")
		m_delay_decompressor = true;

	if (m_decryptor)
	{
		m_iblocksize = m_decryptor->OptimalBlockSize();
		m_oblocksize = m_encryptor->OptimalBlockSize();
	}
}

void crypto_engine::reset()
{
	m_packet.reset();
	m_encryptor.reset(nullptr);
	m_decryptor.reset(nullptr);
	m_signer.reset(nullptr);
	m_verifier.reset(nullptr);
	m_compressor.reset(nullptr);
	m_decompressor.reset(nullptr);
	m_delay_decompressor = m_delay_compressor = false;
	m_in_seq_nr = m_out_seq_nr = 0;
	m_iblocksize = m_oblocksize = 8;
}

blob crypto_engine::get_next_block(boost::asio::streambuf& buffer, bool empty)
{
	blob block(m_iblocksize);
	buffer.sgetn(reinterpret_cast<char *>(block.data()), m_iblocksize);

	if (m_decryptor)
	{
		blob data(m_iblocksize);
		m_decryptor->ProcessData(data.data(), block.data(), m_iblocksize);
		std::swap(data, block);
	}

	if (m_verifier)
	{
		if (empty)
		{
			for (int32_t i = 3; i >= 0; --i)
			{
				uint8_t b = m_in_seq_nr >> (i * 8);
				m_verifier->Update(&b, 1);
			}
		}

		m_verifier->Update(block.data(), block.size());
	}

	return block;
}

std::unique_ptr<ipacket> crypto_engine::get_next_packet(boost::asio::streambuf& buffer, boost::system::error_code& ec)
{
	if (not m_packet)
		m_packet = std::make_unique<ipacket>();

	bool complete_and_verified = false;

	while (buffer.size() >= m_iblocksize)
	{
		if (not m_packet->complete())
			m_packet->append(get_next_block(buffer, m_packet->empty()));

		if (m_packet->complete())
		{
			if (m_verifier)
			{
				if (buffer.size() < m_verifier->DigestSize())
					break;

				blob digest(m_verifier->DigestSize());
				buffer.sgetn(reinterpret_cast<char *>(digest.data()), m_verifier->DigestSize());

				if (not m_verifier->Verify(digest.data()))
				{
					ec = error::make_error_code(error::mac_error);
					break;
				}
			}

			if (m_decompressor)
				m_packet->decompress(*m_decompressor, ec);

			++m_in_seq_nr;

			complete_and_verified = true;
			break;
		}
	}

	return complete_and_verified ? std::move(m_packet) : std::unique_ptr<ipacket>();
}


std::unique_ptr<boost::asio::streambuf> crypto_engine::get_next_request(opacket&& p)
{
	auto request = std::make_unique<boost::asio::streambuf>();

	if (m_compressor)
	{
		boost::system::error_code ec;
		p.compress(*m_compressor, ec);

		if (ec)
			throw ec;
	}

	io::filtering_stream<io::output> out;
	if (m_encryptor)
		out.push(packet_encryptor(*m_encryptor, *m_signer, m_oblocksize, m_out_seq_nr));
	out.push(*request);

	p.write(out, m_oblocksize);

	++m_out_seq_nr;

	return request;
}

void crypto_engine::enable_compression()
{
	if (m_delay_compressor)
		m_compressor.reset(new compression_helper(true));

	if (m_delay_decompressor)
		m_decompressor.reset(new compression_helper(false));
}

}


