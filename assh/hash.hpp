//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include <assh/config.hpp>

#include <vector>
#include <cryptopp/integer.h>
#include <cryptopp/sha.h>

#include <assh/packet.hpp>

namespace assh
{

template<typename HAlg>
class hash
{
  public:
						hash() {}

	hash&				update(const CryptoPP::Integer& v)
						{
							opacket p;
							p << v;
							return update(static_cast<std::vector<uint8>>(p));
						}

	hash&				update(const std::vector<uint8>& v)
						{
							m_hash.Update(&v[0], v.size());
							return *this;
						}
						
	hash&				update(const std::string& v)
						{
							m_hash.Update(reinterpret_cast<const uint8*>(v.c_str()), v.length());
							return *this;
						}
						
	hash&				update(const char* v)
						{
							m_hash.Update(v, std::strlen(v));
							return *this;
						}
						
	hash&				update(uint8 v)
						{
							m_hash.Update(&v, 1);
							return *this;
						}
	
	std::vector<uint8>	final()
						{
							std::vector<uint8> result(m_hash.DigestSize());
							m_hash.Final(&result[0]);
							return result;
						}

  private:
						hash(const hash&);
	hash&				operator=(const hash&);

	HAlg				m_hash;
};

template<typename H, typename T>
hash<H>& operator|(hash<H>& h, T t)
{
	return h.update(t);
}

}
