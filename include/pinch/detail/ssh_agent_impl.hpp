//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include "pinch/ssh_agent.hpp"
#include "pinch/types.hpp"

namespace pinch
{

class ssh_private_key_impl
{
  public:
	void reference();
	void release();

	virtual blob sign(const blob &session_id, const opacket &data) = 0;

	virtual std::string get_type() const = 0;

	blob get_blob() const
	{
		return m_blob;
	}

	virtual blob get_hash() const = 0;
	virtual std::string get_comment() const = 0;

	static void create_list(std::vector<ssh_private_key> &keys);

  protected:
	ssh_private_key_impl(const blob &b);
	virtual ~ssh_private_key_impl();

	blob m_blob;

  private:
	ssh_private_key_impl(const ssh_private_key_impl &) = delete;
	ssh_private_key_impl &operator=(const ssh_private_key_impl &) = delete;

	int32_t m_refcount;
};

void expose_pageant(bool expose);

} // namespace pinch
