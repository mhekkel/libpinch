//        Copyright Maarten L. Hekkelman 2013-2021
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <pinch/pinch.hpp>

#include <random>

#include <boost/algorithm/string.hpp>

#include <zlib.h>

#include <pinch/channel.hpp>
#include <pinch/packet.hpp>

namespace ba = boost::algorithm;

namespace pinch
{

struct compression_helper_impl
{
	z_stream m_zstream;
	bool m_deflate;
};

compression_helper::compression_helper(bool deflate)
	: m_impl(new compression_helper_impl)
{
	m_impl->m_deflate = deflate;

	memset(&m_impl->m_zstream, 0, sizeof(z_stream));

	int err;
	if (deflate)
		err = deflateInit(&m_impl->m_zstream, Z_BEST_SPEED);
	else
		err = inflateInit(&m_impl->m_zstream);
	if (err != Z_OK)
		throw std::runtime_error("error initializing zlib");
}

compression_helper::~compression_helper()
{
	if (m_impl->m_deflate)
		deflateEnd(&m_impl->m_zstream);
	else
		inflateEnd(&m_impl->m_zstream);
	delete m_impl;
}

compression_helper::operator z_stream &()
{
	return m_impl->m_zstream;
}

// --------------------------------------------------------------------

opacket::opacket()
	: m_data(0)
{
}

opacket::opacket(message_type message)
	: m_data(1)
{
	m_data[0] = message;
}

opacket::opacket(const opacket &rhs)
	: m_data(rhs.m_data)
{
}

opacket::opacket(opacket &&rhs)
	: m_data(move(rhs.m_data))
{
}

opacket &opacket::operator=(opacket &&rhs)
{
	if (this != &rhs)
		m_data = move(rhs.m_data);
	return *this;
}

opacket &opacket::operator=(const opacket &rhs)
{
	if (this != &rhs)
		m_data = rhs.m_data;
	return *this;
}

void opacket::compress(compression_helper &compressor, boost::system::error_code &ec)
{
	z_stream &zstream(compressor);

	zstream.next_in = m_data.data();
	zstream.avail_in = m_data.size();
	zstream.total_in = 0;

	blob data;
	data.reserve(m_data.size());

	uint8_t buffer[1024];

	zstream.next_out = buffer;
	zstream.avail_out = sizeof(buffer);
	zstream.total_out = 0;

	int err;
	do
	{
		err = deflate(&zstream, Z_SYNC_FLUSH);

		if (sizeof(buffer) - zstream.avail_out > 0)
		{
			copy(buffer, buffer + sizeof(buffer) - zstream.avail_out,
			     back_inserter(data));
			zstream.next_out = buffer;
			zstream.avail_out = sizeof(buffer);
		}
	} while (err >= Z_OK);

	if (err != Z_BUF_ERROR)
		ec = error::make_error_code(error::compression_error);

	swap(data, m_data);
}

void opacket::write(std::ostream &os, int blocksize) const
{
	static std::random_device rng;

	assert(blocksize < std::numeric_limits<uint8_t>::max());

	uint8_t header[5];
	blob padding;

	uint32_t size = m_data.size() + 5;
	uint32_t padding_size = blocksize - (size % blocksize);
	if (padding_size == static_cast<uint32_t>(blocksize))
		padding_size = 0;

	while (padding_size < 4)
		padding_size += blocksize;

	std::uniform_int_distribution<uint8_t> rb;
	for (uint32_t i = 0; i < padding_size; ++i)
		padding.push_back(rb(rng));

	header[4] = static_cast<uint8_t>(padding_size);

	size += padding_size - 4;
	header[3] = static_cast<uint8_t>(size);
	size >>= 8;
	header[2] = static_cast<uint8_t>(size);
	size >>= 8;
	header[1] = static_cast<uint8_t>(size);
	size >>= 8;
	header[0] = static_cast<uint8_t>(size);

	os.write(reinterpret_cast<const char *>(header), 5);
	os.write(reinterpret_cast<const char *>(m_data.data()), m_data.size());
	os.write(reinterpret_cast<const char *>(padding.data()), padding_size);
}

//void opacket::append(const uint8_t* data, uint32_t size)
//{
//	operator<<(size);
//	m_data.insert(m_data.end(), data, data + size);
//}

opacket &opacket::operator<<(const char *v)
{
	assert(v != nullptr);
	uint32_t len = strlen(v);
	this->operator<<(len);
	const uint8_t *s = reinterpret_cast<const uint8_t *>(v);
	m_data.insert(m_data.end(), s, s + len);
	return *this;
}

opacket &opacket::operator<<(const std::string &v)
{
	uint32_t len = v.length();
	this->operator<<(len);
	const uint8_t *s = reinterpret_cast<const uint8_t *>(v.c_str());
	m_data.insert(m_data.end(), s, s + len);
	return *this;
}

opacket &opacket::operator<<(const std::vector<std::string> &v)
{
	return this->operator<<(ba::join(v, ","));
}

opacket &opacket::operator<<(const char *v[])
{
	std::string s;
	bool first = true;

	for (const char **i = v; *i != nullptr; ++i)
	{
		if (not first)
			s += ',';
		first = false;
		s += *i;
	}

	return this->operator<<(s);
}

opacket &opacket::operator<<(const CryptoPP::Integer &v)
{
	uint32_t l = v.MinEncodedSize(CryptoPP::Integer::SIGNED);
	operator<<(l);
	uint32_t s = m_data.size();
	m_data.insert(m_data.end(), l, uint8_t(0));
	v.Encode(m_data.data() + s, l, CryptoPP::Integer::SIGNED);

	assert(n + l + sizeof(uint32_t) == m_data.size());

	return *this;
}

opacket &opacket::operator<<(const blob &v)
{
	operator<<(static_cast<uint32_t>(v.size()));
	m_data.insert(m_data.end(), v.begin(), v.end());
	return *this;
}

opacket &opacket::operator<<(const ipacket &v)
{
	operator<<(v.m_length);
	m_data.insert(m_data.end(), v.m_data, v.m_data + v.m_length);
	return *this;
}

opacket &opacket::operator<<(const opacket &v)
{
	const blob &data(v);
	return operator<<(data);
}

// --------------------------------------------------------------------

ipacket::ipacket()
	: m_message(msg_undefined)
	, m_padding(0)
	, m_owned(false)
	, m_complete(false)
	, m_offset(0)
	, m_length(0)
	, m_data(nullptr)
{
}

ipacket::ipacket(const ipacket &rhs)
	: m_message(rhs.m_message)
	, m_padding(rhs.m_padding)
	, m_owned(false)
	, m_complete(rhs.m_complete)
	, m_offset(rhs.m_offset)
	, m_length(rhs.m_length)
	, m_data(rhs.m_data)
{
}

ipacket::ipacket(ipacket &&rhs)
	: m_message(rhs.m_message)
	, m_padding(rhs.m_padding)
	, m_owned(rhs.m_owned)
	, m_offset(rhs.m_offset)
	, m_length(rhs.m_length)
	, m_data(rhs.m_data)
{
	rhs.m_message = msg_undefined;
	rhs.m_padding = 0;
	rhs.m_owned = false;
	rhs.m_offset = rhs.m_length = 0;
	rhs.m_data = nullptr;
}

ipacket::ipacket(const uint8_t *data, size_t size)
{
	m_data = new uint8_t[size];
	memcpy(m_data, data, size);
	m_owned = true;
	m_length = size;
	m_padding = 0;
	m_message = (message_type)m_data[0];
	m_offset = 1;
}

ipacket::~ipacket()
{
#if DEBUG
	if (m_owned and m_data != nullptr)
	{
		memset(m_data, 0xcc, m_length);
		delete[] m_data;
	}
#else
	if (m_owned)
		delete[] m_data;
#endif
}

ipacket &ipacket::operator=(ipacket &&rhs)
{
	if (this != &rhs)
	{
		m_message = rhs.m_message;
		rhs.m_message = msg_undefined;
		m_padding = rhs.m_padding;
		rhs.m_padding = 0;
		m_complete = rhs.m_complete;
		rhs.m_complete = false;
		m_owned = rhs.m_owned;
		rhs.m_owned = false;
		m_offset = rhs.m_offset;
		rhs.m_offset = 0;
		m_length = rhs.m_length;
		rhs.m_length = 0;
		m_data = rhs.m_data;
		rhs.m_data = nullptr;
	}

	return *this;
}

void ipacket::decompress(compression_helper &decompressor, boost::system::error_code &ec)
{
	assert(m_complete);

	z_stream &zstream(decompressor);

	zstream.next_in = m_data;
	zstream.avail_in = m_length;
	zstream.total_in = 0;

	blob data;
	uint8_t buffer[1024];

	zstream.next_out = buffer;
	zstream.avail_out = sizeof(buffer);
	zstream.total_out = 0;

	int err;
	do
	{
		err = inflate(&zstream, Z_SYNC_FLUSH);

		if (sizeof(buffer) - zstream.avail_out > 0)
		{
			copy(buffer, buffer + sizeof(buffer) - zstream.avail_out,
			     back_inserter(data));
			zstream.next_out = buffer;
			zstream.avail_out = sizeof(buffer);
		}
	} while (err >= Z_OK);

	if (err != Z_BUF_ERROR)
		ec = error::make_error_code(error::compression_error);
	else
	{
		if (m_owned)
			delete[] m_data;

		m_length = data.size();
		m_data = new uint8_t[m_length];
		copy(data.begin(), data.end(), m_data);
		m_owned = true;

		m_message = static_cast<message_type>(m_data[0]);
		m_offset = 1;
	}
}

bool ipacket::complete()
{
	return m_complete;
}

bool ipacket::empty()
{
	return m_length == 0 or m_data == nullptr;
}

void ipacket::clear()
{
#if DEBUG
	if (m_owned and m_data != nullptr)
		memset(m_data, 0xcc, m_length);
#endif

	if (m_owned)
		delete[] m_data;
	m_data = nullptr;

	m_message = msg_undefined;
	m_padding = 0;
	m_owned = true;
	m_complete = false;
	m_length = 0;
	m_offset = 0;
}

void ipacket::append(const blob &block)
{
	if (m_complete)
		throw packet_exception();

	if (m_data == nullptr)
	{
		assert(block.size() >= 8);

		for (int i = 0; i < 4; ++i)
			m_length = m_length << 8 | static_cast<uint8_t>(block[i]);

		if (m_length > kMaxPacketSize + 32) // weird, allow some overhead?
			throw packet_exception();

		m_length -= 1; // the padding uint8_t

		m_message = static_cast<message_type>(block[5]);
		m_padding = block[4];
		m_owned = true;
		m_offset = 1;
		m_data = new uint8_t[m_length];

		if (block.size() > m_length + 5)
			throw packet_exception();

		std::copy(block.begin() + 5, block.end(), m_data);
		m_offset = block.size() - 5;
	}
	else
	{
		size_t n = m_length - m_offset;
		if (n > block.size())
			n = block.size();

		for (size_t i = 0; i < n; ++i, ++m_offset)
			m_data[m_offset] = block[i];
	}

	if (m_offset == m_length) // this was the last block
	{
		m_complete = true;
		m_length -= m_padding;
		m_offset = 1;
	}
}

size_t ipacket::read(const char *data, size_t size)
{
	size_t result = 0;

	if (m_complete)
		throw packet_exception();

	if (m_data == nullptr)
	{
		while (m_offset < 4 and size > 0)
		{
			m_length = m_length << 8 | static_cast<uint8_t>(*data);
			++data;
			--size;
			++m_offset;
			++result;
		}

		if (m_offset == 4)
		{
			if (m_length > kMaxPacketSize)
				throw packet_exception();

			m_padding = 0;
			m_owned = true;
			m_offset = 1;
			m_data = new uint8_t[m_length];

			uint32_t k = size;
			if (k > m_length)
				k = m_length;
			result += k;

			memcpy(m_data, data, k);

			m_offset = k;
		}
	}
	else
	{
		result = m_length - m_offset;
		if (result > size)
			result = size;

		memcpy(m_data + m_offset, data, result);
		m_offset += result;
	}

	if (m_offset == m_length) // this was the last block
	{
		m_message = static_cast<message_type>(m_data[0]);
		m_complete = true;
		m_offset = 1;
	}

	return result;
}

ipacket &ipacket::operator>>(std::string &v)
{
	uint32_t len;
	this->operator>>(len);
	if (m_offset + len > m_length)
		throw packet_exception();

	const char *s = reinterpret_cast<const char *>(&m_data[m_offset]);
	v.assign(s, len);
	m_offset += len;

	return *this;
}

ipacket &ipacket::operator>>(std::vector<std::string> &v)
{
	std::string s;
	this->operator>>(s);
	ba::split(v, s, ba::is_any_of(","));
	return *this;
}

ipacket &ipacket::operator>>(CryptoPP::Integer &v)
{
	uint32_t l;
	operator>>(l);

	if (l > m_length)
		throw packet_exception();

	v.Decode(&m_data[m_offset], l, CryptoPP::Integer::SIGNED);
	m_offset += l;

	return *this;
}

ipacket &ipacket::operator>>(ipacket &v)
{
#if DEBUG
	if (v.m_owned and v.m_data != nullptr)
		memset(v.m_data, 0xcc, v.m_length);
#endif

	uint32_t l;
	operator>>(l);

	if (l > m_length)
		throw packet_exception();

	if (v.m_owned)
		delete[] v.m_data;

	v.m_message = msg_undefined;
	v.m_padding = 0;
	v.m_owned = false;
	v.m_complete = true;
	v.m_data = m_data + m_offset;
	v.m_length = l;

	m_offset += l;

	return *this;
}

ipacket &ipacket::operator>>(std::pair<const char *, size_t> &v)
{
	uint32_t l;
	operator>>(l);

	if (l > m_length)
		throw packet_exception();

	v.first = reinterpret_cast<const char *>(&m_data[m_offset]);
	v.second = l;

	m_offset += l;

	return *this;
}

ipacket &ipacket::operator>>(blob &v)
{
	uint32_t l;
	operator>>(l);

	if (l > m_length)
		throw packet_exception();

	v.assign(&m_data[m_offset], &m_data[m_offset + l]);

	m_offset += l;

	return *this;
}

bool operator==(const opacket &lhs, const ipacket &rhs)
{
	return lhs.m_data.size() == rhs.m_length and memcmp(lhs.m_data.data(), rhs.m_data, rhs.m_length) == 0;
}

bool operator==(const ipacket &lhs, const opacket &rhs)
{
	return rhs.m_data.size() == lhs.m_length and memcmp(rhs.m_data.data(), lhs.m_data, lhs.m_length) == 0;
}

} // namespace pinch
