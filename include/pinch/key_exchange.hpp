//        Copyright Maarten L. Hekkelman 2013-2021
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

/// \file key_exchange.hpp
/// Definition of the key exchange object

#include "pinch/packet.hpp"

namespace pinch
{

// --------------------------------------------------------------------
// The defaults for our protocols

extern const std::string
	kKeyExchangeAlgorithms,
	kServerHostKeyAlgorithms, kEncryptionAlgorithms, kMacAlgorithms, kCompressionAlgorithms;

// --------------------------------------------------------------------

/// \brief Return the first common protocol for \a server and \a client
std::string choose_protocol(const std::string &server, const std::string &client);

// --------------------------------------------------------------------

struct key_exchange_impl;

/// \brief The class encapsulating the key exchange algorithm
class key_exchange
{
  public:
	/// \brief Set a preferred algorithm
	///
	/// This method should obviously be called before connecting.
	///
	/// \param alg			The algorithm to use
	/// \param dir			The direction. Tip: use direction::both
	/// \param preferred	The comma separated list of algorithms, ordered by preferrence
	static void set_algorithm(algorithm alg, direction dir, const std::string &preferred);

	/// \brief Constructor for a new connection
	///
	/// \param host_version The version string provided by the host
	key_exchange(const std::string &host_version);

	/// \brief Constructor for a rekey event
	///
	/// \param host_version The version string provided by the host
	/// \param session_id	The session ID created in the initial key exchange
	key_exchange(const std::string &host_version, const blob &session_id);

	/// \brief destructor
	~key_exchange();

	key_exchange(const key_exchange &) = delete;
	key_exchange &operator=(const key_exchange &) = delete;

	/// \brief Return a packet with msg_kexinit and our preferred algo's
	opacket init();

	/// \brief Process a message during key exchange
	///
	/// \param in	The incomming packet
	/// \param out	Might be filled, or not...
	/// \param ec	Will contain an error code in case of trouble
	/// \result		Returns true if the message was successfully handled
	bool process(ipacket &in, opacket &out, asio_system_ns::error_code &ec);

	/// \brief Process a message during key exchange
	/// This method throws a asio_system_ns::system_error on failure.
	///
	/// \param in	The incomming packet
	/// \result		Returns a packet that may be empty, or not
	opacket process(ipacket &in);

	/// \brief Enumerator for the keys, see standard
	enum key_enum
	{
		A,
		B,
		C,
		D,
		E,
		F
	};

	/// \brief Return the key data for key \a k
	const uint8_t *key(key_enum k) const;

	/// \brief Return the session ID as created
	const blob &session_id() const { return m_session_id; }

	/// \brief Return the final encryption algorithm chosen for \a dir
	std::string get_encryption_protocol(direction dir) const;

	/// \brief Return the final verification algorithm chosen for \a dir
	std::string get_verification_protocol(direction dir) const;

	/// \brief Return the final compression algorithm chosen for \a dir
	std::string get_compression_protocol(direction dir) const;

	/// \brief Return the private key signing algorithm for the host key
	const std::string &get_host_key_pk_type() const { return m_pk_type; }

	/// \brief Return the public key for the host
	const blob &get_host_key() const { return m_host_key; }

  protected:
	friend struct key_exchange_impl;

	/// \brief The host payload packet
	ipacket host_payload() const;

	/// \brief process the kexinit message
	void process_kexinit(ipacket &in, opacket &out, asio_system_ns::error_code &ec);

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
		s_alg_enc_s2c, s_alg_enc_c2s, s_alg_ver_s2c, s_alg_ver_c2s, s_alg_cmp_s2c, s_alg_cmp_c2s,
		s_server_host_key;
};

} // namespace pinch
