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

packet::~packet()
{
	delete[] m_padding;
}

void packet::to_buffers(uint32 blocksize, vector<boost::asio::const_buffer>& buffers)
{
	assert(blocksize < numeric_limits<uint8>::max());
	
	add_data(buffers);
	
	uint32 size = boost::asio::buffer_size(buffers);
	uint32 padding_size = blocksize - (size % blocksize);
	if (padding_size == blocksize)
		padding_size = 0;
	
	m_header[4] = static_cast<uint8>(padding_size);
	
	size += padding_size - 4;
	m_header[3] = static_cast<uint8>(size % 256);	size >>= 8;
	m_header[2] = static_cast<uint8>(size % 256);	size >>= 8;
	m_header[1] = static_cast<uint8>(size % 256);	size >>= 8;
	m_header[0] = static_cast<uint8>(size % 256);
	
	delete[] m_padding;
	m_padding = new uint8[padding_size];
	r::uniform_int_distribution<uint8> rb;

	for (uint32 i = 0; i < padding_size; ++i)
		m_padding[i] = rb(rng);
	
	buffers.push_back(boost::asio::const_buffer(m_padding, padding_size));
}

void packet::add_data(vector<boost::asio::const_buffer>& buffers) const
{
	buffers.push_back(boost::asio::const_buffer(m_header, 5));
	buffers.push_back(boost::asio::const_buffer(&m_message, 1));
}
	
}
