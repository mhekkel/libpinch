//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <assh/config.hpp>

#include <cryptopp/sha.h>

#include <boost/random/random_device.hpp>
#include <boost/random/uniform_int_distribution.hpp>
#include <boost/algorithm/string.hpp>

#include <assh/packet.hpp>

using namespace std;
namespace r = boost::random;
namespace ba = boost::algorithm;

namespace assh
{

r::random_device rng;

opacket::opacket()
{
}

opacket::opacket(message_type message)
	: m_data(1)
{
	m_data[0] = message;
}

opacket::opacket(opacket&& rhs)
	: m_data(move(rhs.m_data))
{
}

opacket& opacket::operator=(opacket&& rhs)
{
	if (this != &rhs)
		m_data= move(rhs.m_data);
	return *this;
}

void opacket::write(ostream& os, int blocksize) const
{
	assert(blocksize < numeric_limits<uint8>::max());

	uint8 header[5];
	vector<uint8> padding;
	
	uint32 size = m_data.size() + 5;
	uint32 padding_size = blocksize - (size % blocksize);
	if (padding_size == blocksize)
		padding_size = 0;
	
	r::uniform_int_distribution<uint8> rb;
	for (uint32 i = 0; i < padding_size; ++i)
		padding.push_back(rb(rng));
	
	header[4] = static_cast<uint8>(padding_size);
	
	size += padding_size - 4;
	header[3] = static_cast<uint8>(size % 256);	size >>= 8;
	header[2] = static_cast<uint8>(size % 256);	size >>= 8;
	header[1] = static_cast<uint8>(size % 256);	size >>= 8;
	header[0] = static_cast<uint8>(size % 256);

	os.write(reinterpret_cast<const char*>(header), 5);
	os.write(reinterpret_cast<const char*>(&m_data[0]), m_data.size());
	os.write(reinterpret_cast<const char*>(&padding[0]), padding_size);
}

opacket& opacket::operator<<(const char* v)
{
	assert(v != nullptr);
	uint32 len = strlen(v);
	this->operator<<(len);
	const uint8* s = reinterpret_cast<const uint8*>(v);
	m_data.insert(m_data.end(), s, s + len);
	return *this;
}

opacket& opacket::operator<<(const string& v)
{
	uint32 len = v.length();
	this->operator<<(len);
	const uint8* s = reinterpret_cast<const uint8*>(v.c_str());
	m_data.insert(m_data.end(), s, s + len);
	return *this;
}

opacket& opacket::operator<<(const vector<string>& v)
{
	return this->operator<<(ba::join(v, ","));
}

opacket& opacket::operator<<(const char* v[])
{
	string s;
	bool first = true;

	for (const char** i = v; *i != nullptr; ++i)
	{
		if (not first)
			s += ',';
		first = false;
		s += *i;
	} 

	return this->operator<<(s);
}

opacket& opacket::operator<<(const CryptoPP::Integer& v)
{
	uint32 n = m_data.size();

	uint32 l = v.MinEncodedSize(CryptoPP::Integer::SIGNED);
	operator<<(l);
	uint32 s = m_data.size();
	m_data.insert(m_data.end(), l, uint8(0));
	v.Encode(&m_data[0] + s, l, CryptoPP::Integer::SIGNED);
	
	assert(n + l + sizeof(uint32) == m_data.size());
	
	return *this;
}

vector<uint8> opacket::hash() const
{
	CryptoPP::SHA1 hash;
	uint32 dLen = hash.DigestSize();
	vector<uint8> result(dLen);
	hash.Update(&m_data[0], m_data.size());
	hash.Final(&result[0]);
	return result;
}

ipacket::ipacket()
	: m_message(undefined)
	, m_offset(0)
	, m_length(0)
{
}

ipacket::ipacket(const ipacket& rhs)
	: m_message(rhs.m_message)
	, m_data(rhs.m_data)
	, m_offset(rhs.m_offset)
	, m_length(rhs.m_length)
{
}

ipacket::ipacket(ipacket&& rhs)
	: m_message(rhs.m_message)
	, m_data(move(rhs.m_data))
	, m_offset(rhs.m_offset)
	, m_length(rhs.m_length)
{
	rhs.m_message = undefined;
	rhs.m_offset = rhs.m_length = 0;
}

ipacket& ipacket::operator=(ipacket&& rhs)
{
	if (this != &rhs)
	{
		m_message = rhs.m_message;	rhs.m_message = undefined;
		m_data = move(rhs.m_data);
		m_offset = rhs.m_offset;	rhs.m_offset = 0;
		m_length = rhs.m_length;	rhs.m_length = 0;
	}
	
	return *this;
}


bool ipacket::full()
{
	return m_data.size() == m_length + sizeof(uint32);
}

void ipacket::clear()
{
	m_data.clear();
	m_length = 0;
	m_offset = 0;
}

void ipacket::append(const vector<char>& block)
{
	if (m_data.size() == 0)
	{
		assert(block.size() >= 8);

		for (int i = 0; i < 4; ++i)
			m_length = m_length << 8 | static_cast<uint8>(block[i]);

		// that's too much
		m_data.reserve(m_length + sizeof(uint32));
		
		m_message = static_cast<message_type>(block[5]);
		m_offset = 6;
	}

	m_data.insert(m_data.end(), block.begin(), block.end());
}

ipacket& ipacket::operator>>(string& v)
{
	uint32 len;
	this->operator>>(len);
	if (m_offset + len > m_data.size())
		throw packet_exception();
	
	const char* s = reinterpret_cast<const char*>(&m_data[m_offset]);
	v.assign(s, len);
	m_offset += len;
	
	return *this;
}

ipacket& ipacket::operator>>(vector<string>& v)
{
	string s;
	this->operator>>(s);
	ba::split(v, s, ba::is_any_of(","));
	return *this;
}

ipacket& ipacket::operator>>(CryptoPP::Integer& v)
{
	uint32 l;
	operator>>(l);
	
	if (l > m_data.size())
		throw packet_exception();

	v.Decode(&m_data[m_offset], l, CryptoPP::Integer::SIGNED);
	m_offset += l;

	return *this;
}

ipacket& ipacket::operator>>(ipacket& v)
{
	uint32 l;
	operator>>(l);
	
	if (l > m_data.size())
		throw packet_exception();

	v.m_data.assign(m_data.begin() + m_offset, m_data.begin() + m_offset + l);
	m_offset += l;

	return *this;
}

}
