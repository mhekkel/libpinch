//        Copyright Maarten L. Hekkelman 2013-2021
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

/// \file crypto-engine.hpp
/// This file contains the definition of the crypto engine class

#include "pinch/asio.hpp"
#include "pinch/key_exchange.hpp"
#include "pinch/packet.hpp"

#include <mutex>


namespace pinch
{

class crypto_engine;

/// @cond

// --------------------------------------------------------------------
// Wrapper class around stream transformation classes (encyption/decryption)
class transform_data
{
  public:
	transform_data() = default;
	transform_data(const transform_data &) = delete;
	transform_data &operator=(const transform_data &) = delete;
	~transform_data();

	void clear();

	explicit operator bool() { return m_impl != nullptr; }

	void reset_encryptor(const std::string &name, const uint8_t *key, const uint8_t *iv);
	void reset_decryptor(const std::string &name, const uint8_t *key, const uint8_t *iv);

	void process(const uint8_t *in, std::size_t len, uint8_t *out);
	std::size_t get_block_size() const;

  private:
	friend class crypto_engine;

	struct transform_data_impl *m_impl = nullptr;
};

// --------------------------------------------------------------------
// Wrapper class around message authentication classes
class message_authentication_code
{
  public:
	message_authentication_code() = default;
	message_authentication_code(const message_authentication_code &) = delete;
	message_authentication_code &operator=(const message_authentication_code &) = delete;
	~message_authentication_code();

	void clear();

	explicit operator bool() { return m_impl != nullptr; }

	void reset(const std::string &name, const uint8_t *iv);

	void update(const uint8_t *data, std::size_t len);
	bool verify(const uint8_t *signature);

	std::size_t get_digest_size() const;

  private:
	friend class crypto_engine;

	struct message_authentication_code_impl *m_impl = nullptr;
};

/// @endcond

/// --------------------------------------------------------------------
/// \brief the crypto_engine class
///
/// Helper class for encrypting/decrypting and signing/verifying outgoing
/// and incomming messages.
///
/// Keeps track of packet numbers and encapsulates the crypto logic.

class crypto_engine
{
  public:
	/// \brief copy protection
	crypto_engine(const crypto_engine &) = delete;
	crypto_engine &operator=(const crypto_engine &) = delete;

	/// \brief Constructor
	crypto_engine();

	/// \brief Get the connection parameters as a string for direction \a dir
	std::string get_connection_parameters(direction dir) const;

	/// \brief Get the key exchange algorithm used
	std::string get_key_exchange_algorithm() const;

	/// \brief Start using the new keys in \a kex.
	///
	/// The key exchange has finished and kex contains the new keys.
	///
	/// \param kex				The key exchange object containing the new keys
	/// \param authenticated	The connection has already been authenticated (rekey event)
	///							If false, compressing is delayed in case of zlib@openssh.com
	void newkeys(key_exchange &kex, bool authenticated);

	/// \brief If compression is zlib@openssh.com, start using compression from now on
	void enable_compression();

	/// \brief Reset all
	void reset();

	/// \brief Return the next packet extracted from \a buffer
	///
	/// Will return an empty pointer in case the packet is not complete yet
	/// and needs more input.
	std::unique_ptr<ipacket> get_next_packet(asio_ns::streambuf &buffer, asio_system_ns::error_code &ec);

	/// \brief Package the packet in \a p as a streambuf
	std::unique_ptr<asio_ns::streambuf> get_next_request(opacket &&p);

  private:
	/// \brief Fetch the next block of data
	blob get_next_block(asio_ns::streambuf &buffer, bool empty);

	/// @cond

	std::size_t m_iblocksize = 8, m_oblocksize = 8;
	uint32_t m_in_seq_nr = 0, m_out_seq_nr = 0;

	std::string m_alg_kex,
		m_alg_enc_c2s, m_alg_ver_c2s, m_alg_cmp_c2s,
		m_alg_enc_s2c, m_alg_ver_s2c, m_alg_cmp_s2c;

	transform_data m_decryptor;
	transform_data m_encryptor;
	message_authentication_code m_signer;
	message_authentication_code m_verifier;

	std::unique_ptr<compression_helper> m_compressor;
	std::unique_ptr<compression_helper> m_decompressor;
	bool m_delay_compressor, m_delay_decompressor;

	std::unique_ptr<ipacket> m_packet;

	std::mutex m_in_mutex, m_out_mutex;

	/// @endcond
};

} // namespace pinch
