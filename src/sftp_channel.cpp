//        Copyright Maarten L. Hekkelman 2013-2021
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <pinch/pinch.hpp>

#include <pinch/connection.hpp>
#include <pinch/packet.hpp>
#include <pinch/sftp_channel.hpp>

namespace pinch
{

// --------------------------------------------------------------------

enum sftp_messages : uint8_t
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

enum sftp_fxattr_flags : uint32_t
{
	SSH_FILEXFER_ATTR_SIZE = 0x00000001,
	SSH_FILEXFER_ATTR_UIDGID = 0x00000002,
	SSH_FILEXFER_ATTR_PERMISSIONS = 0x00000004,
	SSH_FILEXFER_ATTR_ACMODTIME = 0x00000008,
	SSH_FILEXFER_ATTR_EXTENDED = 0x80000000
};

inline constexpr sftp_fxattr_flags operator|(sftp_fxattr_flags lhs, sftp_fxattr_flags rhs)
{
	return sftp_fxattr_flags((uint32_t)lhs | (uint32_t)rhs);
}

enum sftp_fxf_flags : uint32_t
{
	SSH_FXF_READ = 0x00000001,
	SSH_FXF_WRITE = 0x00000002,
	SSH_FXF_APPEND = 0x00000004,
	SSH_FXF_CREAT = 0x00000008,
	SSH_FXF_TRUNC = 0x00000010,
	SSH_FXF_EXCL = 0x00000020
};

inline constexpr sftp_fxf_flags operator|(sftp_fxf_flags lhs, sftp_fxf_flags rhs)
{
	return sftp_fxf_flags((uint32_t)lhs | (uint32_t)rhs);
}

// --------------------------------------------------------------------

namespace error
{
	namespace detail
	{

		class sftp_category : public boost::system::error_category
		{
		  public:
			const char *name() const BOOST_SYSTEM_NOEXCEPT
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

	} // namespace detail

	boost::system::error_category &sftp_category()
	{
		static detail::sftp_category impl;
		return impl;
	}

} // namespace error

// --------------------------------------------------------------------
//

ipacket &operator>>(ipacket &in, file_attributes &attr)
{
	uint32_t flags;

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
		uint32_t count;

		in >> count;
		while (count-- > 0)
		{
			std::string type, value;
			in >> type >> value;
			attr.extended.push_back(make_pair(type, value));
		}
	}

	return in;
}

// --------------------------------------------------------------------
//

sftp_channel::sftp_channel(std::shared_ptr<basic_connection> connection)
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
	for (auto h : m_sftp_ops)
	{
		h->complete(error::make_error_code(error::ssh_fx_connection_lost));
		delete h;
	}
	m_sftp_ops.clear();

	channel::closed();
}

void sftp_channel::opened()
{
	channel::opened();

	send_request_and_command("subsystem", "sftp");
}

void sftp_channel::receive_data(const char *data, size_t size)
{
	while (size > 0)
	{
		if (m_packet.empty() and size < 4)
		{
			close(); // we have an empty packet and less than 4 bytes...
			break;   // simply fail. I hope this will never happen
		}

		size_t r = m_packet.read(data, size);

		if (m_packet.complete())
		{
			try
			{
				if (static_cast<pinch::sftp_messages>(m_packet.message()) == SSH_FXP_VERSION)
				{
					auto op = std::move(m_init_op);

					if (not op)
					{
						close();
						return;
					}

					m_packet >> m_version;
					op->m_version = m_version;
					op->complete();
				}
				else
					process_packet();
			}
			catch (...)
			{
			}
			m_packet.clear();
		}

		data += r;
		size -= r;
	}
}

void sftp_channel::process_packet()
{
	uint32_t id;

	m_packet >> id;

	auto op = fetch_op(id);

	if (op == nullptr)
		close();
	else
	{
		opacket out = op->process(m_packet);

		if (not out.empty())
			write(std::move(out));

		if (op->is_complete())
		{
			m_sftp_ops.erase(remove(m_sftp_ops.begin(), m_sftp_ops.end(), op), m_sftp_ops.end());
			delete op;
		}
	}
}

void sftp_channel::do_init(std::unique_ptr<detail::sftp_init_op> op)
{
	channel::async_open([op = std::move(op), this](const boost::system::error_code& ec) mutable
	{
		if (ec)
			op->complete(ec);
		else
		{
			opacket out((message_type)SSH_FXP_INIT);
			out << uint32_t(op->m_version);
			write(std::move(out));

			m_init_op = std::move(op);
		}
	});
}

void sftp_channel::do_readdir(std::unique_ptr<detail::sftp_readdir_op> op)
{
	opacket out((message_type)SSH_FXP_OPENDIR);
	out << op->m_id << op->m_path;
	write(std::move(out));

	m_sftp_ops.push_back(op.release());
}

// --------------------------------------------------------------------

namespace detail
{

	opacket sftp_readdir_op::process(ipacket &p)
	{
		opacket out;

		switch ((sftp_messages)p.message())
		{
			case SSH_FXP_STATUS:
			{
				uint32_t error;
				std::string message, language_tag;
				p >> error >> message >> language_tag;

				if (not error and not m_handle.empty())
				{
					out = opacket((message_type)SSH_FXP_CLOSE);
					out << m_id << m_handle;
				}

				complete(error::make_error_code(error::sftp_error(error)));
				break;
			}

			case SSH_FXP_HANDLE:
			{
				p >> m_handle;
				out = opacket((message_type)SSH_FXP_READDIR);
				out << m_id << m_handle;
				break;
			}

			case SSH_FXP_NAME:
			{
				uint32_t count;
				p >> count;
				while (count--)
				{
					std::string name, longname;
					file_attributes attr;

					p >> name >> longname >> attr;

					m_files.emplace_back(name, longname, attr);
				}

				if (out.empty())
				{
					out = opacket((message_type)SSH_FXP_READDIR);
					out << m_id << m_handle;
				}
				break;
			}

			default:;
		}

		return out;
	}

} // namespace detail

} // namespace pinch
