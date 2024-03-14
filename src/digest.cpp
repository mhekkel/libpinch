//        Copyright Maarten L. Hekkelman 2013-2021
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)


#include "pinch/digest.hpp"

#include <limits.h>
#include <memory.h>

#include <cassert>
#include <random>
#include <streambuf>

namespace pinch
{

// --------------------------------------------------------------------
// encoding/decoding

const char kBase64CharTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const uint8_t kBase64IndexTable[128] = {
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	62,  // +
	128, // not used
	128, // not used
	128, // not used
	63,  // /
	52,  // 0
	53,  // 1
	54,  // 2
	55,  // 3
	56,  // 4
	57,  // 5
	58,  // 6
	59,  // 7
	60,  // 8
	61,  // 9
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	0,   // A
	1,   // B
	2,   // C
	3,   // D
	4,   // E
	5,   // F
	6,   // G
	7,   // H
	8,   // I
	9,   // J
	10,  // K
	11,  // L
	12,  // M
	13,  // N
	14,  // O
	15,  // P
	16,  // Q
	17,  // R
	18,  // S
	19,  // T
	20,  // U
	21,  // V
	22,  // W
	23,  // X
	24,  // Y
	25,  // Z
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	26,  // a
	27,  // b
	28,  // c
	29,  // d
	30,  // e
	31,  // f
	32,  // g
	33,  // h
	34,  // i
	35,  // j
	36,  // k
	37,  // l
	38,  // m
	39,  // n
	40,  // o
	41,  // p
	42,  // q
	43,  // r
	44,  // s
	45,  // t
	46,  // u
	47,  // v
	48,  // w
	49,  // x
	50,  // y
	51,  // z
	128, // not used
	128, // not used
	128, // not used
	128, // not used
	128, // not used
};

inline size_t sextet(char ch)
{
	if (ch < '+' or ch > 'z' or kBase64IndexTable[static_cast<uint8_t>(ch)] >= 128)
		throw invalid_base64();

	return kBase64IndexTable[static_cast<uint8_t>(ch)];
}

std::string encode_base64(std::string_view data, size_t wrap_width)
{
	std::string::size_type n = data.length();
	std::string::size_type m = 4 * (n / 3);
	if (n % 3)
		m += 4;

	if (wrap_width != 0)
		m += (m / wrap_width) + 1;

	std::string result;
	result.reserve(m);

	auto ch = data.begin();
	size_t l = 0;

	while (n > 0)
	{
		char s[4] = {'=', '=', '=', '='};

		switch (n)
		{
			case 1:
			{
				uint8_t i = *ch++;
				s[0] = kBase64CharTable[i >> 2];
				s[1] = kBase64CharTable[(i << 4) bitand 0x03f];

				n -= 1;
				break;
			}

			case 2:
			{
				uint8_t i1 = *ch++;
				uint8_t i2 = *ch++;

				s[0] = kBase64CharTable[i1 >> 2];
				s[1] = kBase64CharTable[(i1 << 4 bitor i2 >> 4) bitand 0x03f];
				s[2] = kBase64CharTable[(i2 << 2) bitand 0x03f];

				n -= 2;
				break;
			}

			default:
			{
				uint8_t i1 = *ch++;
				uint8_t i2 = *ch++;
				uint8_t i3 = *ch++;

				s[0] = kBase64CharTable[i1 >> 2];
				s[1] = kBase64CharTable[(i1 << 4 bitor i2 >> 4) bitand 0x03f];
				s[2] = kBase64CharTable[(i2 << 2 bitor i3 >> 6) bitand 0x03f];
				s[3] = kBase64CharTable[i3 bitand 0x03f];

				n -= 3;
				break;
			}
		}

		if (wrap_width == 0)
			result.append(s, s + 4);
		else
		{
			for (size_t i = 0; i < 4; ++i)
			{
				if (l == wrap_width)
				{
					result.append(1, '\n');
					l = 0;
				}

				result.append(1, s[i]);
				++l;
			}
		}
	}

	if (wrap_width != 0)
		result.append(1, '\n');

	assert(result.length() == m);

	return result;
}

std::string encode_base64(const blob &data)
{
	return encode_base64(std::string_view(reinterpret_cast<const char *>(data.data()), data.size()), 0);
}

blob decode_base64(std::string_view data)
{
	size_t n = data.length();
	size_t m = 3 * (n / 4);

	blob result;
	result.reserve(m);

	auto i = data.begin();

	while (i != data.end())
	{
		uint8_t sxt[4] = {};
		int b = 0, c = 3;

		while (b < 4)
		{
			if (i == data.end())
				break;

			char ch = *i++;

			switch (ch)
			{
				case ' ':
				case '\t':
				case '\n':
				case '\r':
					break;

				case '=':
					if (b == 2 and *i++ == '=')
					{
						c = 1;
						b = 4;
					}
					else if (b == 3)
					{
						c = 2;
						b = 4;
					}
					else
						throw invalid_base64();
					break;

				default:
					sxt[b] = sextet(ch);
					++b;
					break;
			}
		}

		if (b == 4)
		{
			result.push_back(sxt[0] << 2 bitor sxt[1] >> 4);
			if (c >= 2)
				result.push_back(sxt[1] << 4 bitor sxt[2] >> 2);
			if (c == 3)
				result.push_back(sxt[2] << 6 bitor sxt[3]);
		}
		else if (b != 0)
			throw invalid_base64();
	}

	return result;
}

// --------------------------------------------------------------------
// random

blob random_hash()
{
	std::random_device rng;

	union
	{
		uint32_t data[5];
		uint8_t s[4 * 5];
	} v = {{rng(), rng(), rng(), rng(), rng()}};

	return {v.s, v.s + sizeof(v)};
}

// --------------------------------------------------------------------
// hashes

// --------------------------------------------------------------------

static inline uint32_t rotl32(uint32_t n, unsigned int c)
{
	const unsigned int mask = (CHAR_BIT * sizeof(n) - 1); // assumes width is a power of 2.

	// assert ( (c<=mask) &&"rotate by type width or more");
	c &= mask;
	return (n << c) bitor (n >> ((-c) & mask));
}

static inline uint32_t rotr32(uint32_t n, unsigned int c)
{
	const unsigned int mask = (CHAR_BIT * sizeof(n) - 1);

	// assert ( (c<=mask) &&"rotate by type width or more");
	c &= mask;
	return (n >> c) bitor (n << ((-c) & mask));
}

// --------------------------------------------------------------------

struct hash_impl
{
	virtual ~hash_impl() = default;

	virtual void write_bit_length(uint64_t l, uint8_t *b) = 0;
	virtual void transform(const uint8_t *data) = 0;
	virtual blob final() = 0;
};

// --------------------------------------------------------------------

struct sha1_hash_impl : public hash_impl
{
	using word_type = uint32_t;
	static const size_t word_count = 5;
	static const size_t block_size = 64;
	static const size_t digest_size = word_count * sizeof(word_type);

	word_type m_h[word_count];

	virtual void init()
	{
		m_h[0] = 0x67452301;
		m_h[1] = 0xEFCDAB89;
		m_h[2] = 0x98BADCFE;
		m_h[3] = 0x10325476;
		m_h[4] = 0xC3D2E1F0;
	}

	virtual void write_bit_length(uint64_t l, uint8_t *b)
	{
#if defined(BYTE_ORDER) and BYTE_ORDER == BIG_ENDIAN
		memcpy(b, &l, sizeof(l));
#else
		b[0] = l >> 56;
		b[1] = l >> 48;
		b[2] = l >> 40;
		b[3] = l >> 32;
		b[4] = l >> 24;
		b[5] = l >> 16;
		b[6] = l >> 8;
		b[7] = l >> 0;
#endif
	}

	virtual void transform(const uint8_t *data)
	{
		union
		{
			uint8_t s[64];
			uint32_t w[80];
		} w;

#if defined(BYTE_ORDER) and BYTE_ORDER == BIG_ENDIAN
		memcpy(w.s, data, 64);
#else
		auto p = data;
		for (size_t i = 0; i < 16; ++i)
		{
			w.s[i * 4 + 3] = *p++;
			w.s[i * 4 + 2] = *p++;
			w.s[i * 4 + 1] = *p++;
			w.s[i * 4 + 0] = *p++;
		}
#endif

		for (size_t i = 16; i < 80; ++i)
			w.w[i] = rotl32(w.w[i - 3] xor w.w[i - 8] xor w.w[i - 14] xor w.w[i - 16], 1);

		word_type wv[word_count];

		for (size_t i = 0; i < word_count; ++i)
			wv[i] = m_h[i];

		for (size_t i = 0; i < 80; ++i)
		{
			uint32_t f, k;
			if (i < 20)
			{
				f = (wv[1] bitand wv[2]) bitor ((compl wv[1]) bitand wv[3]);
				k = 0x5A827999;
			}
			else if (i < 40)
			{
				f = wv[1] xor wv[2] xor wv[3];
				k = 0x6ED9EBA1;
			}
			else if (i < 60)
			{
				f = (wv[1] bitand wv[2]) bitor (wv[1] bitand wv[3]) bitor (wv[2] bitand wv[3]);
				k = 0x8F1BBCDC;
			}
			else
			{
				f = wv[1] xor wv[2] xor wv[3];
				k = 0xCA62C1D6;
			}

			uint32_t t = rotl32(wv[0], 5) + f + wv[4] + k + w.w[i];

			wv[4] = wv[3];
			wv[3] = wv[2];
			wv[2] = rotl32(wv[1], 30);
			wv[1] = wv[0];
			wv[0] = t;
		}

		for (size_t i = 0; i < word_count; ++i)
			m_h[i] += wv[i];
	}

	virtual blob final()
	{
		blob result(digest_size, '\0');

#if defined(BYTE_ORDER) and BYTE_ORDER == BIG_ENDIAN
		memcpy(const_cast<char *>(result.data()), &m_h, digest_size);
#else
		auto s = result.begin();
		for (size_t i = 0; i < word_count; ++i)
		{
			*s++ = static_cast<char>(m_h[i] >> 24);
			*s++ = static_cast<char>(m_h[i] >> 16);
			*s++ = static_cast<char>(m_h[i] >> 8);
			*s++ = static_cast<char>(m_h[i] >> 0);
		}
#endif

		return result;
	}
};

// --------------------------------------------------------------------

struct sha256_hash_impl : public hash_impl
{
	using word_type = uint32_t;
	static const size_t word_count = 8;
	static const size_t block_size = 64;
	static const size_t digest_size = word_count * sizeof(word_type);

	word_type m_h[word_count];

	virtual void init()
	{
		m_h[0] = 0x6a09e667;
		m_h[1] = 0xbb67ae85;
		m_h[2] = 0x3c6ef372;
		m_h[3] = 0xa54ff53a;
		m_h[4] = 0x510e527f;
		m_h[5] = 0x9b05688c;
		m_h[6] = 0x1f83d9ab;
		m_h[7] = 0x5be0cd19;
	}

	virtual void write_bit_length(uint64_t l, uint8_t *b)
	{
#if defined(BYTE_ORDER) and BYTE_ORDER == BIG_ENDIAN
		memcpy(b, &l, sizeof(l));
#else
		b[0] = l >> 56;
		b[1] = l >> 48;
		b[2] = l >> 40;
		b[3] = l >> 32;
		b[4] = l >> 24;
		b[5] = l >> 16;
		b[6] = l >> 8;
		b[7] = l >> 0;
#endif
	}

	virtual void transform(const uint8_t *data)
	{
		static const uint32_t k[] = {
			0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
			0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
			0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
			0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
			0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
			0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
			0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
			0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

		word_type wv[word_count];
		for (size_t i = 0; i < word_count; ++i)
			wv[i] = m_h[i];

		union
		{
			uint8_t s[64];
			uint32_t w[64];
		} w;

#if defined(BYTE_ORDER) and BYTE_ORDER == BIG_ENDIAN
		memcpy(w.w, data, 64);
#else
		auto p = data;
		for (size_t i = 0; i < 16; ++i)
		{
			w.s[i * 4 + 3] = *p++;
			w.s[i * 4 + 2] = *p++;
			w.s[i * 4 + 1] = *p++;
			w.s[i * 4 + 0] = *p++;
		}
#endif

		for (size_t i = 16; i < 64; ++i)
		{
			auto s0 = rotr32(w.w[i - 15], 7) xor rotr32(w.w[i - 15], 18) xor (w.w[i - 15] >> 3);
			auto s1 = rotr32(w.w[i - 2], 17) xor rotr32(w.w[i - 2], 19) xor (w.w[i - 2] >> 10);
			w.w[i] = w.w[i - 16] + s0 + w.w[i - 7] + s1;
		}

		for (size_t i = 0; i < 64; ++i)
		{
			uint32_t S1 = rotr32(wv[4], 6) xor rotr32(wv[4], 11) xor rotr32(wv[4], 25);
			uint32_t ch = (wv[4] bitand wv[5]) xor (compl wv[4] bitand wv[6]);
			uint32_t t1 = wv[7] + S1 + ch + k[i] + w.w[i];
			uint32_t S0 = rotr32(wv[0], 2) xor rotr32(wv[0], 13) xor rotr32(wv[0], 22);
			uint32_t maj = (wv[0] bitand wv[1]) xor (wv[0] bitand wv[2]) xor (wv[1] bitand wv[2]);
			uint32_t t2 = S0 + maj;

			wv[7] = wv[6];
			wv[6] = wv[5];
			wv[5] = wv[4];
			wv[4] = wv[3] + t1;
			wv[3] = wv[2];
			wv[2] = wv[1];
			wv[1] = wv[0];
			wv[0] = t1 + t2;
		}

		for (size_t i = 0; i < word_count; ++i)
			m_h[i] += wv[i];
	}

	virtual blob final()
	{
		blob result(digest_size, '\0');

#if defined(BYTE_ORDER) and BYTE_ORDER == BIG_ENDIAN
		memcpy(const_cast<char *>(result.data()), &m_h, digest_size);
#else
		auto s = result.begin();
		for (size_t i = 0; i < word_count; ++i)
		{
			*s++ = static_cast<char>(m_h[i] >> 24);
			*s++ = static_cast<char>(m_h[i] >> 16);
			*s++ = static_cast<char>(m_h[i] >> 8);
			*s++ = static_cast<char>(m_h[i] >> 0);
		}
#endif

		return result;
	}
};

// --------------------------------------------------------------------

template <typename I>
class hash_base : public I
{
  public:
	using word_type = typename I::word_type;
	static const size_t word_count = I::word_count;
	static const size_t block_size = I::block_size;
	static const size_t digest_size = I::digest_size;

	hash_base()
	{
		init();
	}

	void init()
	{
		I::init();

		m_data_length = 0;
		m_bit_length = 0;
	}

	void update(std::string_view data);
	void update(const blob &data);
	void update(const uint8_t *data, size_t n);

	using I::transform;
	blob final();

  private:
	uint8_t m_data[block_size];
	uint32_t m_data_length;
	int64_t m_bit_length;
};

template <typename I>
void hash_base<I>::update(std::string_view data)
{
	update(reinterpret_cast<const uint8_t *>(data.data()), data.size());
}

template <typename I>
void hash_base<I>::update(const blob &data)
{
	update(data.data(), data.size());
}

template <typename I>
void hash_base<I>::update(const uint8_t *p, size_t length)
{
	m_bit_length += length * 8;

	if (m_data_length > 0)
	{
		uint32_t n = block_size - m_data_length;
		if (n > length)
			n = static_cast<uint32_t>(length);

		memcpy(m_data + m_data_length, p, n);
		m_data_length += n;

		if (m_data_length == block_size)
		{
			transform(m_data);
			m_data_length = 0;
		}

		p += n;
		length -= n;
	}

	while (length >= block_size)
	{
		transform(p);
		p += block_size;
		length -= block_size;
	}

	if (length > 0)
	{
		memcpy(m_data, p, length);
		m_data_length += static_cast<uint32_t>(length);
	}
}

template <typename I>
blob hash_base<I>::final()
{
	m_data[m_data_length] = 0x80;
	++m_data_length;
	std::fill(m_data + m_data_length, m_data + block_size, 0);

	if (block_size - m_data_length < 8)
	{
		transform(m_data);
		std::fill(m_data, m_data + block_size - 8, 0);
	}

	I::write_bit_length(m_bit_length, m_data + block_size - 8);

	transform(m_data);
	std::fill(m_data, m_data + block_size, 0);

	auto result = I::final();
	init();
	return result;
}

// using MD5 = hash_base<md5_hash_impl>;
using SHA1 = hash_base<sha1_hash_impl>;
using SHA256 = hash_base<sha256_hash_impl>;

// --------------------------------------------------------------------

blob sha1(std::string_view data)
{
	SHA1 h;
	h.init();
	h.update(data);
	return h.final();
}

blob sha1(std::streambuf &data)
{
	SHA1 h;
	h.init();

	while (data.in_avail() > 0)
	{
		uint8_t buffer[256];
		auto n = data.sgetn(reinterpret_cast<char *>(buffer), sizeof(buffer));
		h.update(buffer, n);
	}

	return h.final();
}

blob sha256(std::string_view data)
{
	SHA256 h;
	h.init();
	h.update(data);
	return h.final();
}

// --------------------------------------------------------------------
// hmac

template <typename H>
class HMAC
{
  public:
	static const size_t block_size = H::block_size;
	static const size_t digest_size = H::digest_size;

	HMAC(blob key)
		: m_ipad(block_size, '\x36')
		, m_opad(block_size, '\x5c')
	{
		if (key.size() > block_size)
		{
			H keyHash;
			keyHash.update(key);
			key = keyHash.final();
		}

		assert(key.size() < block_size);

		for (size_t i = 0; i < key.size(); ++i)
		{
			m_opad[i] ^= key[i];
			m_ipad[i] ^= key[i];
		}
	}

	HMAC &update(std::string_view data)
	{
		if (not m_inner_updated)
		{
			m_inner.update(m_ipad);
			m_inner_updated = true;
		}

		m_inner.update(data);
		return *this;
	}

	HMAC &update(const blob &data)
	{
		if (not m_inner_updated)
		{
			m_inner.update(m_ipad);
			m_inner_updated = true;
		}

		m_inner.update(data);
		return *this;
	}

	blob final()
	{
		H outer;
		outer.update(m_opad);
		outer.update(m_inner.final());
		m_inner_updated = false;
		return outer.final();
	}

  private:
	std::string m_ipad, m_opad;
	bool m_inner_updated = false;
	H m_inner;
};

blob hmac_sha1(std::string_view message, const blob &key)
{
	return HMAC<SHA1>(key).update(message).final();
}

blob hmac_sha256(std::string_view message, const blob &key)
{
	return HMAC<SHA256>(key).update(message).final();
}

} // namespace pinch
