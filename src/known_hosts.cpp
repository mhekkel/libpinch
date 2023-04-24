//           Copyright Maarten L. Hekkelman 2021
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)


#include "pinch/digest.hpp"
#include "pinch/known_hosts.hpp"

#include <istream>

namespace pinch
{

// --------------------------------------------------------------------

host_key_state known_hosts::host_key::compare(const std::string &host_name, const std::string &algorithm, const pinch::blob &key) const
{
	host_key_state result = host_key_state::no_match;

	// Is the hostname hashed?
	if (m_host_name.substr(0, 3) == "|1|")
	{
		auto s1 = m_host_name.find('|', 3);
		if (s1 != std::string::npos)
		{
			auto salt = decode_base64(m_host_name.substr(3, s1 - 3));
			auto hash = decode_base64(m_host_name.substr(s1 + 1));

			if (hmac_sha1(host_name, salt) == hash)
				result = host_key_state::match;
		}
	}
	else if (host_name == m_host_name)
		result = host_key_state::match;

	if (result == host_key_state::match and m_algorithm == algorithm and m_key != key)
		result = host_key_state::keys_differ;

	return result;
}

// --------------------------------------------------------------------

void known_hosts::load_host_file(std::istream &file)
{
	std::lock_guard lock(m_mutex);
	m_host_keys.clear();

	std::string line;
	while (std::getline(file, line))
	{
		auto t1 = line.find(' ');
		if (t1 == std::string::npos)
			continue;

		auto t2 = line.find(' ', t1 + 1);
		if (t2 == std::string::npos)
			continue;

		try
		{
			m_host_keys.emplace_back(host_key{
				line.substr(0, t1),
				line.substr(t1 + 1, t2 - t1 - 1),
				decode_base64(line.substr(t2 + 1))});
		}
		catch (...)
		{
		}
	}
}

void known_hosts::save_host_file(std::ostream &file)
{
	std::lock_guard lock(m_mutex);

	for (auto &kh : m_host_keys)
		file << kh.m_host_name << ' ' << kh.m_algorithm << ' ' << encode_base64(kh.m_key) << std::endl;
}

// --------------------------------------------------------------------

void known_hosts::add_host_key(const std::string &host, const std::string &algorithm, const std::string &key)
{
	std::lock_guard lock(m_mutex);

	m_host_keys.emplace_back(host_key{host, algorithm, decode_base64(key)});
}

void known_hosts::add_host_key(const std::string &host, const std::string &algorithm, const blob &key)
{
	std::lock_guard lock(m_mutex);

	blob salt = random_hash();

	std::string name = "|1|" + encode_base64(salt) + '|';

	name += encode_base64(hmac_sha1(host, salt));

	m_host_keys.emplace_back(host_key{name, algorithm, key});
}

host_key_state known_hosts::accept_host_key(const std::string &host, const std::string &algorithm, const blob &key)
{
	std::lock_guard lock(m_mutex);

	host_key_state state = host_key_state::no_match;

	for (auto &hk : m_host_keys)
	{
		state = hk.compare(host, algorithm, key);

		if (state == host_key_state::match or state == host_key_state::keys_differ)
			break;
	}

	return state;
}

} // namespace pinch
