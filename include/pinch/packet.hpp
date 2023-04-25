//        Copyright Maarten L. Hekkelman 2013-2021
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

/// \brief Encapsulation of the contenst of a SSH packet

#include "pinch/asio.hpp"
#include "pinch/types.hpp"

#include <cryptopp/cryptlib.h>

#include <ostream>
#include <system_error>
#include <type_traits>

namespace CryptoPP
{
class Integer;
}

/// forward declaration
struct z_stream_s;

namespace pinch
{

/// forward declarations
class ipacket;
class opacket;

/// \brief Helper class for doing zlib compression
class compression_helper
{
  public:
	compression_helper(bool deflate);
	~compression_helper();

	operator z_stream_s &();

  private:
	struct compression_helper_impl *m_impl;
};

/// \brief exception thrown in case of an invalid packet
class packet_exception : public std::exception
{
};

/// \brief The messages known (according to the standard)
enum message_type : uint8_t
{
	msg_undefined,

	msg_disconnect = 1,
	msg_ignore,
	msg_unimplemented,
	msg_debug,
	msg_service_request,
	msg_service_accept,

	msg_kexinit = 20,
	msg_newkeys,

	msg_kex_dh_init = 30,
	msg_kex_dh_reply,
	msg_kex_dh_gex_group = 31,
	msg_kex_dh_gex_init,
	msg_kex_dh_gex_reply,
	msg_kex_dh_gex_request,

	msg_userauth_request = 50,
	msg_userauth_failure,
	msg_userauth_success,
	msg_userauth_banner,

	msg_userauth_info_request = 60,
	msg_userauth_info_response,

	msg_global_request = 80,
	msg_request_success,
	msg_request_failure,

	msg_channel_open = 90,
	msg_channel_open_confirmation,
	msg_channel_open_failure,
	msg_channel_window_adjust,
	msg_channel_data,
	msg_channel_extended_data,
	msg_channel_eof,
	msg_channel_close,
	msg_channel_request,
	msg_channel_success,
	msg_channel_failure,

	// ssh_agent messages

	/* Messages for the authentication agent connection. */
	SSH_AGENTC_REQUEST_RSA_IDENTITIES = 1,
	SSH_AGENT_RSA_IDENTITIES_ANSWER,
	SSH_AGENTC_RSA_CHALLENGE,
	SSH_AGENT_RSA_RESPONSE,
	SSH_AGENT_FAILURE,
	SSH_AGENT_SUCCESS,
	SSH_AGENTC_ADD_RSA_IDENTITY,
	SSH_AGENTC_REMOVE_RSA_IDENTITY,
	SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES,

	/* private OpenSSH extensions for SSH2 */
	SSH2_AGENTC_REQUEST_IDENTITIES = 11,
	SSH2_AGENT_IDENTITIES_ANSWER,
	SSH2_AGENTC_SIGN_REQUEST,
	SSH2_AGENT_SIGN_RESPONSE,
	SSH2_AGENTC_ADD_IDENTITY = 17,
	SSH2_AGENTC_REMOVE_IDENTITY,
	SSH2_AGENTC_REMOVE_ALL_IDENTITIES,

	/* smartcard */
	SSH_AGENTC_ADD_SMARTCARD_KEY,
	SSH_AGENTC_REMOVE_SMARTCARD_KEY,

	/* lock/unlock the agent */
	SSH_AGENTC_LOCK,
	SSH_AGENTC_UNLOCK,

	/* add key with constraints */
	SSH_AGENTC_ADD_RSA_ID_CONSTRAINED,
	SSH2_AGENTC_ADD_ID_CONSTRAINED,
	SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED,

	SSH_AGENT_CONSTRAIN_LIFETIME = 1,
	SSH_AGENT_CONSTRAIN_CONFIRM,

	/* extended failure messages */
	SSH2_AGENT_FAILURE = 30,

	/* additional error code for ssh.com's ssh-agent2 */
	SSH_COM_AGENT2_FAILURE = 102,

	SSH_AGENT_OLD_SIGNATURE = 0x01

};

/// \brief the outgoing packet
class opacket
{
  public:
	/// \brief compare the contents of an ipacket with an opacket
	friend bool operator==(const opacket &, const ipacket &);

	/// \brief compare the contents of an ipacket with an opacket
	friend bool operator==(const ipacket &, const opacket &);

	/// \brief Simple constructor, create fully empty packet
	opacket();

	/// \brief Construtor
	///
	/// \param message	The data will start with this message
	opacket(message_type message);

	/// \brief Construtor
	///
	/// \param message	The data will start with message \a message and will contain the optional data elements \a v
	template <typename... Ts>
	opacket(message_type message, Ts ...v)
		: opacket(message)
	{
		(operator<<(std::forward<Ts>(v)), ...);
	}

	/// \brief Copy constructor
	opacket(const opacket &rhs);

	/// \brief Move constructor
	opacket(opacket &&rhs);

	/// \brief Copy operator
	opacket &operator=(const opacket &rhs);

	/// \brief Move operator
	opacket &operator=(opacket &&rhs);

	/// \brief Compress the contents of the packet
	void compress(compression_helper &compressor, system_ns::error_code &ec);

	/// \brief Write the contents of the packet to \a os padded to \a blocksize
	void write(std::ostream &os, int blocksize) const;

	/// \brief View the contents of this packet
	operator blob() const { return m_data; }

	/// \brief The contents of the packet as a std::string_view
	operator std::string_view() const { return std::string_view(reinterpret_cast<const char *>(m_data.data()), m_data.size()); }

	/// \brief Return if this packet contains any sensible data
	bool empty() const { return m_data.empty() or static_cast<message_type>(m_data[0]) == msg_undefined; }

	/// \brief Access to the underlying data
	const uint8_t *data() const { return m_data.data(); }

	/// \brief Return the size of the data contained in this packet
	std::size_t size() const { return m_data.size(); }

	/// \brief Return true if the packet is not empty
	explicit operator bool() const { return not empty(); }

	/// \brief Store the value \a v
	template <typename T, typename std::enable_if_t<std::is_integral_v<T>, int> = 0>
	opacket &operator<<(T v)
	{
		for (int i = sizeof(T) - 1; i >= 0; --i)
			m_data.push_back(static_cast<uint8_t>(v >> (i * 8)));

		return *this;
	}

	opacket &operator<<(std::string_view v);
	opacket &operator<<(const std::vector<std::string> &v);
	opacket &operator<<(const blob &v);
	opacket &operator<<(const CryptoPP::Integer &v);
	opacket &operator<<(const opacket &v);
	opacket &operator<<(const ipacket &v);

  protected:
	blob m_data;
};

struct skip_string_t
{
};

struct skip_offset
{
	constexpr skip_offset(int offset)
		: m_offset(offset)
	{
	}
	constexpr skip_offset(skip_string_t)
		: m_offset(-1)
	{
	}
	int m_offset;
};

constexpr skip_offset skip_str = skip_offset(skip_string_t{});
constexpr skip_offset skip(int offset) { return skip_offset(offset); }

/// \brief Incomming packet
class ipacket
{
  public:
	friend class opacket;

	friend bool operator==(const opacket &, const ipacket &);
	friend bool operator==(const ipacket &, const opacket &);

	/// \brief Constructor taking a sequence number
	ipacket(uint32_t nr = 0);

	/// \brief Copy constructor
	ipacket(const ipacket &rhs);

	/// \brief Move constructor
	ipacket(ipacket &&rhs);

	/// \brief Constructor taking raw data
	ipacket(const uint8_t *data, std::size_t size);

	/// \brief Constructor creating a new ipacket from a blob
	ipacket(message_type msg, const blob &b);

	/// \brief destructor
	~ipacket();

	/// \brief Copy operator
	ipacket &operator=(const ipacket &rhs);

	/// \brief Move operator
	ipacket &operator=(ipacket &&rhs);

	/// \brief Return true if the packet is complete, i.e. it contains all the data it should contain
	bool complete();

	/// \brief Return true if the packet is completely empty
	bool empty();

	/// \brief Clear the packet
	void clear();

	/// \brief Return the packet sequence number
	uint32_t nr() const { return m_number; }

	/// \brief Decompress the contents
	void decompress(compression_helper &decompressor, system_ns::error_code &ec);

	/// \brief The size of the data
	uint32_t size() const { return m_length; }

	/// \brief Append the contents of \a block to this packet
	void append(const blob &block);

	/// \brief Append the raw data \a data with size \a size to this packet
	std::size_t read(const char *data, std::size_t size);

	/// \brief Set the message byte of this packet
	void message(message_type msg) { m_message = msg; }

	/// \brief Get the message byte of this packet
	message_type message() const { return m_message; }

	/// \brief Get the message byte of this packet
	operator message_type() const { return m_message; }

	/// \brief Compare the message byte of this packet with \a msg
	bool operator!=(message_type msg) const
	{
		return m_message != msg;
	}

	/// \brief Compare the message byte of this packet with \a msg
	bool operator==(message_type msg) const
	{
		return m_message == msg;
	}

	/// \brief Return a copy of the data as a blob
	operator blob() const { return blob(m_data, m_data + m_length); }

	/// \brief Read data values from an ipacket
	template <typename T, typename std::enable_if_t<std::is_integral_v<T>, int> = 0>
	ipacket &operator>>(T &v)
	{
		v = 0;

		if (m_offset + sizeof(T) > m_length)
			throw packet_exception();

		for (int i = sizeof(T) - 1; i >= 0; --i)
			v = v << 8 | m_data[m_offset++];

		return *this;
	}

	ipacket &operator>>(std::string &v);
	ipacket &operator>>(std::vector<std::string> &v);
	ipacket &operator>>(blob &v);
	ipacket &operator>>(CryptoPP::Integer &v);
	ipacket &operator>>(ipacket &v);
	ipacket &operator>>(std::pair<const char *, std::size_t> &v);

	/// \brief Skip over data in a packet.
	///
	/// Skip over a fixed number of bytes, or a string
	/// \param s	Skip offset, can be either skip(offset) or skip_str
	ipacket &operator>>(skip_offset s)
	{
		if (s.m_offset == -1)
		{
			uint32_t len;
			this->operator>>(len);
			if (m_offset + len > m_length)
				throw packet_exception();
			m_offset += len;
		}
		else
			m_offset += s.m_offset;

		return *this;
	}

	friend std::ostream &operator<<(std::ostream &os, ipacket &p);

  protected:
	message_type m_message;
	uint8_t m_padding;
	bool m_owned;
	bool m_complete;
	uint32_t m_number = 0;
	uint32_t m_offset, m_length;
	uint8_t *m_data;
};

} // namespace pinch
