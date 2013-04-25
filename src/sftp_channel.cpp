//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <assh/config.hpp>

//#include <boost/bind.hpp>
#include <boost/foreach.hpp>
#define foreach BOOST_FOREACH
//#include <boost/regex.hpp>
//#include <boost/lexical_cast.hpp>

#include <assh/sftp_channel.hpp>
#include <assh/connection.hpp>
#include <assh/packet.hpp>

using namespace std;

namespace assh
{

enum sftp_messages : uint8
{
	SSH_FXP_INIT = 1,
	SSH_FXP_VERSION,
	SSH_FXP_OPEN,
	SSH_FXP_CLOSE,
	SSH_FXP_READ,
	SSH_FXP_WRITE,
	SSH_FXP_LSTAT,
	SSH_FXP_FSTAT,
	SSH_FXP_SETSTAT,
	SSH_FXP_FSETSTAT,
	SSH_FXP_OPENDIR,
	SSH_FXP_READDIR,
	SSH_FXP_REMOVE,
	SSH_FXP_MKDIR,
	SSH_FXP_RMDIR,
	SSH_FXP_REALPATH,
	SSH_FXP_STAT,
	SSH_FXP_RENAME,
	SSH_FXP_READLINK,
	SSH_FXP_SYMLINK,
	
	SSH_FXP_STATUS = 101,
	SSH_FXP_HANDLE,
	SSH_FXP_DATA,
	SSH_FXP_NAME,
	SSH_FXP_ATTRS,
	SSH_FXP_EXTENDED,
	SSH_FXP_EXTENDED_REPLY
};

enum sftp_fxattr_flags : uint32
{
	SSH_FILEXFER_ATTR_SIZE =          0x00000001,
	SSH_FILEXFER_ATTR_UIDGID =        0x00000002,
	SSH_FILEXFER_ATTR_PERMISSIONS =   0x00000004,
	SSH_FILEXFER_ATTR_ACMODTIME =     0x00000008,
	SSH_FILEXFER_ATTR_EXTENDED =      0x80000000
};

sftp_fxattr_flags operator|(sftp_fxattr_flags lhs, sftp_fxattr_flags rhs)
{
	return sftp_fxattr_flags((uint32)lhs | (uint32)rhs);
}

enum sftp_fxf_flags : uint32
{
	SSH_FXF_READ =   0x00000001,
	SSH_FXF_WRITE =  0x00000002,
	SSH_FXF_APPEND = 0x00000004,
	SSH_FXF_CREAT =  0x00000008,
	SSH_FXF_TRUNC =  0x00000010,
	SSH_FXF_EXCL =   0x00000020
};

sftp_fxf_flags operator|(sftp_fxf_flags lhs, sftp_fxf_flags rhs)
{
	return sftp_fxf_flags((uint32)lhs | (uint32)rhs);
}

// --------------------------------------------------------------------

namespace error {
namespace detail {

class sftp_category : public boost::system::error_category
{
  public:

	const char* name() const
	{
		return "sftp";
	}
	
	std::string message(int value) const
	{
		switch (value)
		{
			case ssh_fx_ok:
				return "ok";
			case ssh_fx_eof:
				return "end of file";
			case ssh_fx_no_such_file:
				return "no such file";
			case ssh_fx_permission_denied:
				return "permission denied";
			case ssh_fx_failure:
				return "general failure";
			case ssh_fx_bad_message:
				return "bad message";
			case ssh_fx_no_connection:
				return "no connection";
			case ssh_fx_connection_lost:
				return "connection lost";
			case ssh_fx_op_unsupported:
				return "unsupported operation";
			default:
				return "unknown sftp error";
		}
	}
};

}

boost::system::error_category& sftp_category()
{
	static detail::sftp_category impl;
	return impl;
}

}

// --------------------------------------------------------------------
// 

ipacket& operator>>(ipacket& in, sftp_channel::file_attributes& attr)
{
	uint32 flags;
	
	in >> flags;
	
	if (flags & SSH_FILEXFER_ATTR_SIZE)
		in >> attr.size;
	else
		attr.size = 0;

	if (flags & SSH_FILEXFER_ATTR_UIDGID)
		in >> attr.gid >> attr.uid;
	else
		attr.gid = attr.uid = 0;
		
	if (flags & SSH_FILEXFER_ATTR_PERMISSIONS)
		in >> attr.permissions;
	else
		attr.permissions = 0;
	
	if (flags & SSH_FILEXFER_ATTR_ACMODTIME)
		in >> attr.atime;
	else
		attr.atime = 0;
	
	if (flags & SSH_FILEXFER_ATTR_ACMODTIME)
		in >> attr.mtime;
	else
		attr.mtime = 0;
	
	if (flags & SSH_FILEXFER_ATTR_EXTENDED)
	{
		uint32 count;
		
		in >> count;
		while (count-- > 0)
		{
			string type, value;
			in >> type >> value;
			attr.extended.push_back(make_pair(type, value));
		}
	}
	
	return in;
}

// --------------------------------------------------------------------
// 

void sftp_channel::sftp_reply_handler::handle_handle(const std::string& handle, opacket& out)
{
	m_handle = handle;
	out = opacket((message_type)SSH_FXP_READDIR);
	out << m_id << m_handle;
}

// --------------------------------------------------------------------
// 

sftp_channel::sftp_channel(basic_connection& connection)
	: channel(connection)
	, m_request_id(0)
	, m_version(0)
{
}

sftp_channel::~sftp_channel()
{
}

void sftp_channel::closed()
{
	foreach (sftp_reply_handler* h, m_handlers)
	{
		h->handle_status(error::make_error_code(error::ssh_fx_connection_lost), "", "");
		delete h;
	}
	m_handlers.clear();
	
	channel::closed();
}

void sftp_channel::opened()
{
	channel::opened();
	
	send_request_and_command("subsystem", "sftp");
	
	opacket out((message_type)SSH_FXP_INIT);
	out << uint32(3);
	write(move(out));
}

// --------------------------------------------------------------------
// 

void sftp_channel::read_dir_int(const std::string& path, handle_read_dir_base* handler)
{
	m_handlers.push_back(handler);
	
	opacket out((message_type)SSH_FXP_OPENDIR);
	out << handler->m_id << path;
	write(move(out));
}

void sftp_channel::receive_data(const char* data, size_t size)
{
	while (size > 0)
	{
		if (m_packet.empty() and size < 4)
		{
			close();	// we have an empty packet and less than 4 bytes... 
			break;		// simply fail. I hope this will never happen
		}
		
		size_t r = m_packet.read(data, size);
		
		if (m_packet.complete())
		{
			try
			{
				if (m_packet.message() == SSH_FXP_VERSION)
					m_packet >> m_version;
				else
					process_packet();
			}
			catch (...) {}
			m_packet.clear();
		}
		
		data += r;
		size -= r;
	}
}

void sftp_channel::process_packet()
{
	uint32 id;

	m_packet >> id;
	sftp_reply_handler* handler = fetch_handler(id);
	if (handler == nullptr)
	{
		close();
		return;
	}
	
	opacket out;

	switch (m_packet.message())
	{
		case SSH_FXP_STATUS:
		{
			uint32 error;
			string message, language_tag;
			m_packet >> error >> message >> language_tag;
			handler->handle_status(error::make_error_code(error::sftp_error(error)),
				message, language_tag);
			
			m_handlers.erase(remove(m_handlers.begin(), m_handlers.end(), handler), m_handlers.end());
			delete handler;

			break;
		}

		case SSH_FXP_HANDLE:
		{
			string handle;
			m_packet >> handle;
			handler->handle_handle(handle, out);
			break;
		}

//		case SSH_FXP_DATA:
//		{
//			pair<const char*,size_t> data;
//			m_packet >> data;
//			handler->handle_data(data.data, data.size, out);
//			break;
//		}

		case SSH_FXP_NAME:
		{
			handle_read_dir_base* nh = dynamic_cast<handle_read_dir_base*>(handler);
			if (nh != nullptr)
			{
				uint32 count;
				m_packet >> count;
				while (count--)
				{
					string name, longname;
					file_attributes attr;
				
					m_packet >> name >> longname >> attr;
				
					if (not nh->handle_name(name, longname, attr))
						break;
				}
			}
			
			if (out.empty())
			{
				out = opacket((message_type)SSH_FXP_READDIR);
				out << handler->m_id << handler->m_handle;
			}
			break;
		}

//		case SSH_FXP_ATTRS:
//		{
//			file_attributes attr;
//			m_packet >> attr;
//			handler->handle_attrs(attr, out);
//			break;
//		}
	}
	
	if (not out.empty())
		write(move(out));
}

sftp_channel::sftp_reply_handler* sftp_channel::fetch_handler(uint32 id)
{
	sftp_reply_handler* result = nullptr;
	foreach (sftp_reply_handler* h, m_handlers)
	{
		if (h->m_id == id)
		{
			result = h;
			break;
		}
	}
	
	return result;
}

void sftp_channel::write(opacket&& out)
{
	opacket p = opacket() << move(out);
	send_data(move(p));
}


}
