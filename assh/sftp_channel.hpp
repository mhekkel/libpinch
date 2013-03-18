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

enum sftp_errors
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
	
}

// --------------------------------------------------------------------

class sftp_channel : public channel
{
  public:
					sftp_channel(basic_connection& connection);
					~sftp_channel();

	void			setup(ipacket& in);

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
		virtual void	post_error(const boost::system::error_code& ec, boost::asio::io_service& io_service) = 0;
		virtual void	process_reply(uint8 msg, sftp_channel& ch, ipacket& in) = 0;
	};

	// Handler for handle_read_dir should have the signature:
	//	bool (const boost::system::error_code& ec, const std::string& entry)
	// Returning true means continue, false will stop.

	struct handle_read_dir_base : public sftp_reply_handler
	{
		virtual void	process_entry(
	};

	template<typename Handler>
	struct handle_read_dir : public handle_read_dir_base
	{
						handle_read_dir(Handler&& handler, state_t state = open)
							: m_handler(handler), m_state(state) {}

						handle_read_dir(Handler&& handler, const std::string& handle, state_t state = open)
							: m_handler(handler), m_state(state), m_handle(handle) {}

		virtual void	post_error(const boost::system::error_code& ec, boost::asio::io_service& io_service);
		virtual void	process_reply(uint8 msg, sftp_channel& ch, ipacket& in);
		
		Handler			m_handler;
		enum state_t { open, read, error }	m_state;
		std::string		m_handle;
	};

	template<typename Handler>
	void			read_dir(const std::string& path, Handler&& handler);

	template<typename Handler>
	void			read_file(const std::string& path, Handler&& handler);

	template<typename Handler>
	void			write_file(const std::string& path, Handler&& handler);

  private:

	virtual void	receive_data(const char* data, size_t size);

	virtual void	setup(ipacket& in);
	virtual void	closed();

	uint32				m_request_id;
	uint32				m_version;
	std::vector<uint8>	m_packet;
};

// --------------------------------------------------------------------
// 

template<typename Handler>
void sftp_channel::read_dir(const std::string& path, Handler&& handler)
{
	uint32 request_id = m_request_id++;
	
	opacket out(SSH_FXP_OPENDIR);
	out << request_id << path;
	handle_async(out, request_id, handle_read_dir<Handler>(std::move(handler));
}

template<typename Handler>
void sftp_channel::handle_read_dir<Handler>::process_reply(uint8 msg, sftp_channel& ch, ipacket& in, opacket& out)
{
	if (ec)
		m_handler(ec, "");
	else
	{
		if (m_state == open and msg == SSH_FXP_HANDLE)
		{
			in >> m_handle;
			m_state = read;
		}
		else if (m_state == read and msg == SSH_FXP_NAME)
		{
			uint32 count;
			in >> count;
			
			while (count-- > 0)
			{
				uint32 flags, dummy_i;
				string name, type;
				
				in >> name >> type >> flags;
				
//					// for now...
//				if (ba::starts_with(type, "l"))
//					type = 'd';
				
				if (flags & SSH_FILEXFER_ATTR_SIZE)
					in >> e.size;
	
				if (flags & SSH_FILEXFER_ATTR_UIDGID)
					in >> dummy_i >> dummy_i;
					
				if (flags & SSH_FILEXFER_ATTR_PERMISSIONS)
					in >> dummy_i;
				
				if (flags & SSH_FILEXFER_ATTR_ACMODTIME)
					in >> dummy_i;
				
				if (flags & SSH_FILEXFER_ATTR_ACMODTIME)
					in >> e.date;
				
				if (flags & SSH_FILEXFER_ATTR_EXTENDED)
				{
					in >> dummy_i;
					while (dummy_i-- > 0)
						in >> dummy_s >> dummy_s;
				}
				
				if (not m_handler())
					break;
				
				if (e.name != "." and e.name != "..")
					mDirList.push_back(e);
			}
		}
		
		out = opacket(m_state == read ? SSH_FXP_READDIR : SSH_FXP_CLOSE);
		out << m_handle;
	}
}

}

// --------------------------------------------------------------------
// 

namespace boost {
namespace system {

template<> struct is_error_code_enum<assh::error::sftp_errors>
{
  static const bool value = true;
};

} // namespace system
} // namespace boost

