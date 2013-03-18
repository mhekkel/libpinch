//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <assh/config.hpp>

//#include <boost/bind.hpp>
//#include <boost/foreach.hpp>
//#define foreach BOOST_FOREACH
//#include <boost/regex.hpp>
//#include <boost/lexical_cast.hpp>

#include <assh/sftp_channel.hpp>
#include <assh/connection.hpp>

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

sftp_fxf_flags operator(sftp_fxf_flags lhs, sftp_fxf_flags rhs)
{
	return sftp_fxf_flags((uint32)lhs | (uint32)rhs);
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

sftp_channel::sftp_channel(basic_connection& connection)
	: channel(connection)
	, m_request_id(0)
	, m_version(0)
{
}

sftp_channel::~sftp_channel()
{
}

void sftp_channel::setup(ipacket& in)
{
	send_request_and_command("subsystem", "sftp");
	
	opacket out(SSH_FXP_INIT);
	out << uint32(3);
	m_connection.async_write(move(out));
}

// --------------------------------------------------------------------
// 

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
	opacket out;
	
	switch (m_packet.message())
	{
		case SSH_FXP_VERSION:
		{
			uint32 version;
			m_packet >> m_version;
			break;
		}

		case SSH_FXP_STATUS:
		{
			uint32 error;
			string message, language_tag;
			m_packet >> id >> error >> message >> language_tag;
			handle_error(id, boost::system::make_error_code(error::sftp_errors(error)),
				message, language_tag, out);
			break;
		}

		case SSH_FXP_HANDLE:
		{
			uint32 handle;
			m_packet >> id >> handle;
			set_handle(id, handle, out);
			break;
		}

		case SSH_FXP_DATA:
		{
			pair<const char*,size_t> data;
			m_packet >> id >> data;
			handle_data(id, data, out);
			break;
		}

		case SSH_FXP_NAME:
		{
			uint32 count;
			m_packet >> id >> count;
			while (count--)
			{
				string name, longname;
				file_attributes attr;
				
				in >> name >> longname >> attr;
				
				if (not handle_name(id, name, longname, attr, out))
					break;
			}
			break;
		}

		case SSH_FXP_ATTRS:
		{
			file_attributes attr;
			m_packet >> id >> attr;
			handle_attrs(id, attr, out);
			break;
		}

//		case SSH_FXP_EXTENDED:
//			break;
//
//		case SSH_FXP_EXTENDED_REPLY:
//			break;
	}
	
	if (not out.empty())
		m_connection.async_write(out);
}

}
