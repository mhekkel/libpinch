//           Copyright Maarten L. Hekkelman 2013
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include <pinch/pinch.hpp>

#include <boost/format.hpp>
#include <boost/function.hpp>
#include <boost/asio.hpp>

#include <pinch/channel.hpp>
#include <pinch/packet.hpp>
#include <pinch/operations.hpp>

namespace pinch
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

boost::system::error_category &sftp_category();

inline boost::system::error_code make_error_code(sftp_error e)
{
	return boost::system::error_code(static_cast<int>(e), sftp_category());
}

}

// // --------------------------------------------------------------------

// namespace detail
// {

// class wait_channel_op : public operation
// {
//   public:
// 	boost::system::error_code m_ec;
	
// };

// template <typename Handler, typename IoExecutor>
// class wait_channel_handler : public wait_channel_op
// {
//   public:
// 	wait_channel_handler(Handler&& h, const IoExecutor& io_ex, channel_wait_type type)
// 		: m_handler(std::forward<Handler>(h))
// 		, m_io_executor(io_ex)
// 	{
// 		m_type = type;
// 		handler_work<Handler, IoExecutor>::start(m_handler, m_io_executor);
// 	}

// 	virtual void complete(const boost::system::error_code& ec = {}, std::size_t bytes_transferred = 0) override
// 	{
// 		handler_work<Handler, IoExecutor> w(m_handler, m_io_executor);

// 		binder1<Handler, boost::system::error_code> handler(m_handler, m_ec);

// 		w.complete(handler, handler.m_handler);
// 	}

//   private:
// 	Handler m_handler;
// 	IoExecutor m_io_executor;
// };

// }

// --------------------------------------------------------------------

class sftp_channel : public channel
{
public:
	sftp_channel(std::shared_ptr<basic_connection> connection);
	~sftp_channel();

	virtual void opened() override;
	virtual void closed() override;

	struct file_attributes
	{
		int64_t size;
		uint32_t gid;
		uint32_t uid;
		uint32_t permissions;
		uint32_t atime;
		uint32_t mtime;
		std::list<std::pair<std::string, std::string>> extended;
	};

	struct sftp_reply_handler
	{
		sftp_reply_handler(uint32_t id) : m_id(id) {}
		virtual ~sftp_reply_handler() {}

		virtual void handle_status(const boost::system::error_code &ec,
									const std::string &message, const std::string &language_tag) = 0;

		virtual void handle_handle(const std::string &handle, opacket &out);

		uint32_t m_id;
		std::string m_handle;
	};
	typedef std::list<sftp_reply_handler *> sftp_reply_handler_list;

	// Handler for handle_read_dir should have the signature:
	//	bool (const boost::system::error_code& ec, const std::string& name,
	//			const std::string& longname, const sftp_channel::file_attributes& attr)
	// Returning true means continue, false will stop.

	struct handle_read_dir_base : public sftp_reply_handler
	{
		handle_read_dir_base(uint32_t id) : sftp_reply_handler(id) {}
		virtual bool handle_name(const std::string &name, const std::string &longname, const file_attributes &attr) = 0;
	};

	template <typename Handler>
	struct handle_read_dir : public handle_read_dir_base
	{
		handle_read_dir(uint32_t id, Handler &&handler)
			: handle_read_dir_base(id), m_handler(handler) {}

		virtual void handle_status(const boost::system::error_code &ec,
									const std::string &message, const std::string &language_tag)
		{
			if (ec != make_error_code(error::ssh_fx_eof))
			{
				file_attributes attr = {};
				(void)m_handler(ec, "", "", attr);
			}
		}

		virtual bool handle_name(const std::string &name, const std::string &longname, const file_attributes &attr)
		{
			return m_handler(boost::system::error_code(), name, longname, attr);
		}

		Handler m_handler;
	};

	template <typename Handler>
	void read_dir(const std::string &path, Handler &&handler)
	{
		read_dir_int(path, new handle_read_dir<Handler>(m_request_id++, std::move(handler)));
	}

	//	template<typename Handler>
	//	void			read_file(const std::string& path, Handler&& handler);
	//
	//	template<typename Handler>
	//	void			write_file(const std::string& path, Handler&& handler);

private:
	virtual void receive_data(const char *data, size_t size);
	void process_packet();

	void read_dir_int(const std::string &path, handle_read_dir_base *handler);
	//	void					read_file(handle_read_file_base* handler);

	void write(opacket &&out);

	sftp_reply_handler *fetch_handler(uint32_t id);
	void handle_status(uint32_t id, const boost::system::error_code &ec,
						const std::string &message, const std::string &language_tag,
						opacket &out);
	void handle_handle(uint32_t id, const std::string &handle, opacket &out);
	void handle_data(uint32_t id, const char *data, size_t size, opacket &out);
	bool handle_name(uint32_t id, const std::string &name,
						const std::string &longname, const file_attributes &attr,
						opacket &out);
	void handle_attrs(uint32_t id, const file_attributes &attr, opacket &out);

	uint32_t m_request_id;
	uint32_t m_version;
	ipacket m_packet;
	sftp_reply_handler_list m_handlers;
};

}

// --------------------------------------------------------------------
//

namespace boost::system
{

template <>
struct is_error_code_enum<pinch::error::sftp_error>
{
	static const bool value = true;
};

} // namespace boost::system
