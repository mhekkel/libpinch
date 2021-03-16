//           Copyright Maarten L. Hekkelman 2021
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <pinch/pinch.hpp>

#include <pinch/known_hosts.hpp>

#include <boost/asio.hpp>

// #include <cryptopp/aes.h>
// #include <cryptopp/des.h>
// #include <cryptopp/dsa.h>
// #include <cryptopp/eccrypto.h>
// #include <cryptopp/factory.h>
// #include <cryptopp/files.h>
// #include <cryptopp/filters.h>
// #include <cryptopp/gfpcrypt.h>
// #include <cryptopp/modes.h>
// #include <cryptopp/oids.h>
// #include <cryptopp/osrng.h>
// #include <cryptopp/rsa.h>

// #include <pinch/channel.hpp>
// #include <pinch/crypto-engine.hpp>

// using namespace CryptoPP;

namespace fs = std::filesystem;

namespace pinch
{

void known_hosts::set_host_file(fs::path host_file)
{
	m_host_file = host_file;
}

bool known_hosts::validate(const std::string &host, const std::string &algorithm, const blob &key)
{
	return m_validate_cb ? m_validate_cb(host, algorithm, key) : true;
}

} // namespace pinch
