//           Copyright Maarten L. Hekkelman 2021
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <pinch/pinch.hpp>

#include <fstream>

#include <pinch/digest.hpp>
#include <pinch/known_hosts.hpp>

namespace fs = std::filesystem;

namespace pinch
{

// --------------------------------------------------------------------

bool known_hosts::host_key::compare(const std::string &host_name, const std::string &algorithm, const pinch::blob &key) const
{
	bool result = false;

	// Is the hostname hashed?
	if (m_host_name.substr(0, 3) == "|1|")
	{
		auto s1 = m_host_name.find('|', 3);
		if (s1 != std::string::npos)
		{
			auto salt = decode_base64(m_host_name.substr(3, s1 - 3));
			auto hash = decode_base64(m_host_name.substr(s1 + 1));

			result = hmac_sha1(host_name, salt) == hash;
		}
	}
	else
		result = host_name == m_host_name;
	
	return result and m_algorithm == algorithm and m_key == key;
}

// --------------------------------------------------------------------

void known_hosts::set_host_file(fs::path host_file)
{
	m_host_file = host_file;

	m_host_keys.clear();

	std::ifstream file(host_file);
	if (not file.is_open())
		throw std::runtime_error("Could not open host file " + host_file.string());
	
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
				decode_base64(line.substr(t2 + 1))
			});
		}
		catch (...) { }
	}
}

bool known_hosts::validate(const std::string &host, const std::string &algorithm, const blob &key)
{
	bool result = false;

	for (auto& hk: m_host_keys)
	{
		if (hk.compare(host, algorithm, key))
		{
			result = true;
			break;
		}
	}

	if (not result and m_validate_cb)
	{
		switch (m_validate_cb(host, algorithm, key))
		{
			case host_key_reply::trusted:
				m_host_keys.emplace_back(host_key{ host, algorithm, key });

			case host_key_reply::trust_once:
				result = true;
				break;

			default:
				break;
		}
	}

	return result;
}

} // namespace pinch
