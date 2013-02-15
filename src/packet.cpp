//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <boost/random/random_device.hpp>
#include <boost/random/uniform_int_distribution.hpp>

#include <assh/packet.hpp>

using namespace std;
namespace r = boost::random;

namespace assh
{

r::random_device rng;

packet::packet(message_type message)
	: m_message(message)
	, m_data(6)
	, m_offset(6)
{
	m_data[5] = m_message;
}

packet::~packet()
{
}

void packet::to_buffers(uint32 blocksize, vector<boost::asio::const_buffer>& buffers)
{
	assert(blocksize < numeric_limits<uint8>::max());
	
	uint32 size = m_data.size();
	uint32 padding_size = blocksize - (size % blocksize);
	if (padding_size == blocksize)
		padding_size = 0;
	
	r::uniform_int_distribution<uint8> rb;
	for (uint32 i = 0; i < padding_size; ++i)
		m_data.push_back(rb(rng));
	
	assert(m_data.size() > 0 and m_data.size() % blocksize == 0);
	
	m_data[4] = static_cast<uint8>(padding_size);
	
	size += padding_size - 4;
	m_data[3] = static_cast<uint8>(size % 256);	size >>= 8;
	m_data[2] = static_cast<uint8>(size % 256);	size >>= 8;
	m_data[1] = static_cast<uint8>(size % 256);	size >>= 8;
	m_data[0] = static_cast<uint8>(size % 256);
	
	buffers.push_back(boost::asio::const_buffer(&m_data[0], m_data.size()));
}

packet& packet::operator<<(const char* v)
{
	assert(v != nullptr);
	uint32 len = strlen(v);
	this->operator<<(len);
	const uint8* s = reinterpret_cast<const uint8*>(v);
	m_data.insert(m_data.end(), s, s + len);
	return *this;
}

packet& packet::operator<<(const string& v)
{
	uint32 len = v.length();
	this->operator<<(len);
	const uint8* s = reinterpret_cast<const uint8*>(v.c_str());
	m_data.insert(m_data.end(), s, s + len);
	return *this;
}

packet& packet::operator>>(string& v)
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


}
