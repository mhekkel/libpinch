//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include <assh/config.hpp>

#include <boost/format.hpp>
#include <boost/function.hpp>
#include <boost/asio.hpp>

#include <assh/channel.hpp>
#include <assh/packet.hpp>

namespace assh
{

namespace error
{

enum sftp_error
{
	ssh_fx_ok,
	ssh_fx_eof,
	ssh_fx_no_such_file,
	ssh_fx_permission_denied,
	ssh_fx_failure,
	ssh_fx_bad_message,
	ssh_fx_no_connection,
	ssh_fx_connection_lost,
	ssh_fx_op_unsupported
};

boost::system::error_category& sftp_category();

inline boost::system::error_code make_error_code(sftp_error e)
{
	return boost::system::error_code(static_cast<int>(e), sftp_category());
}
	
}

// --------------------------------------------------------------------

class sftp_channel : public channel
{
  public:
					sftp_channel(basic_connection& connection);
					~sftp_channel();

	virtual void	setup(ipacket& in);
	virtual void	closed();

	struct file_attributes
	{
		uint64		size;
		uint32		gid;
		uint32		uid;
		uint32		permissions;
		uint32		atime;
		uint32		mtime;
		std::list<std::pair<std::string,std::string>>
					extended;
	};

	struct sftp_reply_handler
	{
						sftp_reply_handler(uint32 id) : m_id(id) {}
		virtual			~sftp_reply_handler() {}
		
		virtual void	handle_status(const boost::system::error_code& ec, 
							const std::string& message, const std::string& language_tag) = 0;

		virtual void	handle_handle(const std::string& handle, opacket& out);

		uint32			m_id;
		std::string		m_handle;
	};
	typedef std::list<sftp_reply_handler*>	sftp_reply_handler_list;

	// Handler for handle_read_dir should have the signature:
	//	bool (const boost::system::error_code& ec, const std::string& name,
	//			const std::string& longname, const sftp_channel::file_attributes& attr)
	// Returning true means continue, false will stop.

	struct handle_read_dir_base : public sftp_reply_handler
	{
						handle_read_dir_base(uint32 id) : sftp_reply_handler(id) {}
		virtual bool	handle_name(const std::string& name, const std::string& longname, const file_attributes& attr) = 0;
	};

	template<typename Handler>
	struct handle_read_dir : public handle_read_dir_base
	{
						handle_read_dir(uint32 id, Handler&& handler)
							: handle_read_dir_base(id), m_handler(handler) {}

		virtual void	handle_status(const boost::system::error_code& ec, 
							const std::string& message, const std::string& language_tag)
						{
							if (ec != error::ssh_fx_eof)
							{
								file_attributes attr = {};
								(void)m_handler(ec, "", "", attr);
							}
						}

		virtual bool	handle_name(const std::string& name, const std::string& longname, const file_attributes& attr)
						{
							return m_handler(boost::system::error_code(), name, longname, attr);
						}
		
		Handler			m_handler;
	};

	template<typename Handler>
	void			read_dir(const std::string& path, Handler&& handler)
					{
						read_dir_int(path, new handle_read_dir<Handler>(m_request_id++, std::move(handler)));
					}

//	template<typename Handler>
//	void			read_file(const std::string& path, Handler&& handler);
//
//	template<typename Handler>
//	void			write_file(const std::string& path, Handler&& handler);

  private:

	virtual void			receive_data(const char* data, size_t size);
	void					process_packet();

	void					read_dir_int(const std::string& path, handle_read_dir_base* handler);
//	void					read_file(handle_read_file_base* handler);

	void					write(opacket&& out);

	sftp_reply_handler*		fetch_handler(uint32 id);
	void					handle_status(uint32 id, const boost::system::error_code& ec,
								const std::string& message, const std::string& language_tag,
								opacket& out);
	void					handle_handle(uint32 id, const std::string& handle, opacket& out);
	void					handle_data(uint32 id, const char* data, size_t size, opacket& out);
	bool					handle_name(uint32 id, const std::string& name,
								const std::string& longname, const file_attributes& attr,
								opacket& out);
	void					handle_attrs(uint32 id, const file_attributes& attr, opacket& out);

	uint32					m_request_id;
	uint32					m_version;
	ipacket					m_packet;
	sftp_reply_handler_list	m_handlers;
};

}

// --------------------------------------------------------------------
// 

namespace boost {
namespace system {

template<> struct is_error_code_enum<assh::error::sftp_error>
{
  static const bool value = true;
};

} // namespace system
} // namespace boost

