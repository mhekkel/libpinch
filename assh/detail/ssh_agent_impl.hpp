//          Copyright Maarten L. Hekkelman 2006-2011
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

namespace assh
{

class ssh_private_key_impl
{
  public:
	
	void							reference();
	void							release();

	virtual std::vector<uint8>		sign(const std::vector<uint8>& session_id, const opacket& data) = 0;

	virtual std::vector<uint8>		get_hash() const = 0;
	virtual std::string				get_comment() const = 0;

//	static ssh_private_key_impl*	create_for_hash(const std::string& hash);
	static ssh_private_key_impl*	create_for_blob(ipacket& blob);
	static void						create_list(std::vector<ssh_private_key>& keys);

  protected:

									ssh_private_key_impl();
	virtual							~ssh_private_key_impl();

	friend opacket& operator<<(opacket& p, const ssh_private_key& pk);

	CryptoPP::Integer				m_e, m_n;

  private:
									ssh_private_key_impl(const ssh_private_key_impl&);
	ssh_private_key_impl&			operator=(const ssh_private_key_impl&);
	
	int32							m_refcount;
};

}
