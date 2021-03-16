//           Copyright Maarten L. Hekkelman 2021
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include <pinch/pinch.hpp>
#include <pinch/types.hpp>

#include <boost/asio/dispatch.hpp>

#include <functional>
#include <future>
#include <string>
#include <type_traits>

#include <pinch/digest.hpp>

/// \file This file contains the class known_hosts which is used to keep track of
/// already trusted host keys.

namespace pinch
{

/// \brief The reply from the accept_host_key callback.
enum class host_key_reply
{
	reject,     ///< Do not trust this host key and abort connecting
	trust_once, ///< Trust the host key, but do not store it for future use
	trusted     ///< Trust the key and store it
};

/// \brief The status for a host key's name/alg/key combo.
enum class host_key_state
{
	no_match,    ///< The host key is not known at all
	keys_differ, ///< There is a known host key, but the key values differ
	match        ///< The key is known
};

/// \brief The callback signature
using accept_host_key_handler_type = std::function<host_key_reply(const std::string &host, const std::string &algorithm, const blob &key, host_key_state state)>;

/// \brief The class known_hosts is used to keep track of already trusted host keys.

class known_hosts
{
  public:
	struct host_key
	{
		std::string m_host_name;
		std::string m_algorithm;
		blob m_key;

		host_key_state compare(const std::string &host_name, const std::string &algorithm, const pinch::blob &key) const;
	};

	/// \brief known_hosts is a singleton
	static known_hosts &instance()
	{
		static std::unique_ptr<known_hosts> s_instance(new known_hosts);
		return *s_instance;
	}

	/// \brief Read a host file (in openssh format)
	void load_host_file(std::istream &host_file);

	/// \brief Write a host file (in openssh format)
	void save_host_file(std::ostream &host_file);

	/// \brief Add a single host key, \a key is the base64 encoded key
	void add_host_key(const std::string &host, const std::string &algorithm, const std::string &key)
	{
		m_host_keys.emplace_back(host_key{host, algorithm, decode_base64(key)});
	}

	/// \brief Add a single host key, \a key is the binary, decoded key
	void add_host_key(const std::string &host, const std::string &algorithm, const blob &key);

	/// \brief Return true if the host/algorithm/key pair should be trusted
	bool accept_host_key(const std::string &host, const std::string &algorithm, const blob &key,
		accept_host_key_handler_type& handler);

	/// \brief making the known_hosts iterable, but const only
	using iterator = std::vector<host_key>::const_iterator;

	iterator begin() const { return m_host_keys.cbegin(); }
	iterator end() const { return m_host_keys.cend(); }
	bool empty() const { return m_host_keys.empty(); }
	std::size_t size() const { return m_host_keys.size(); }

  private:
	known_hosts() {}

	known_hosts(const known_hosts &) = delete;
	known_hosts &operator=(const known_hosts &) = delete;

	std::vector<host_key> m_host_keys;

	static std::unique_ptr<known_hosts> s_instance;
};

} // namespace pinch