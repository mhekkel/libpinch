//        Copyright Maarten L. Hekkelman 2013-2021
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

/// \brief A preliminary implementation of SFTP

#include <pinch/channel.hpp>
#include <pinch/pinch.hpp>

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

} // namespace error

// --------------------------------------------------------------------

/// \brief The file attributes as communicated by the server
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

// --------------------------------------------------------------------

namespace detail
{

	class sftp_init_op : public operation
	{
	  public:
		int m_version;
	};

	template <typename Handler, typename IoExecutor>
	class sftp_init_handler : public sftp_init_op
	{
	  public:
		sftp_init_handler(Handler &&h, const IoExecutor &io_ex, int version)
			: m_handler(std::move(h))
			, m_io_executor(io_ex)
			, m_work(m_handler, m_io_executor)
		{
			m_version = version;
		}

		virtual void complete(const boost::system::error_code &ec,
			std::size_t bytes_transferred = 0) override
		{
			binder handler(m_handler, ec, m_version);

			m_work.complete(handler, handler.m_handler);
		}

	  private:
		Handler m_handler;
		IoExecutor m_io_executor;
		handler_work<Handler, IoExecutor> m_work;
	};


	class sftp_operation : public operation
	{
	  public:
		uint32_t m_id;
		std::string m_handle;
		bool m_completed = false;

		bool is_complete() const { return m_completed; }

		virtual opacket process(ipacket &p)
		{
			return {};
		}
	};

	class sftp_readdir_op : public sftp_operation
	{
	  public:
		boost::system::error_code m_ec;
		std::list<std::tuple<std::string, std::string, file_attributes>> m_files;

		virtual opacket process(ipacket &p) override;

		std::string m_path;
		enum { open_dir, read_dir } m_state = open_dir;
	};

	template <typename Handler, typename IoExecutor>
	class sftp_readdir_handler : public sftp_readdir_op
	{
	  public:
		sftp_readdir_handler(Handler &&h, const IoExecutor &io_ex, uint32_t id, const std::string& path)
			: m_handler(std::forward<Handler>(h))
			, m_io_executor(io_ex)
		{
			m_id = id;
			m_path = path;
		}

		virtual void complete(const boost::system::error_code &ec = {}, std::size_t bytes_transferred = 0) override
		{
			handler_work<Handler, IoExecutor> w(m_handler, m_io_executor);

			binder<Handler, boost::system::error_code, std::list<std::tuple<std::string, std::string, file_attributes>>>
				handler(m_handler, m_ec, m_files);

			w.complete(handler, handler.m_handler);

			m_completed = true;
		}

	  private:
		Handler m_handler;
		IoExecutor m_io_executor;
	};

} // namespace detail

// --------------------------------------------------------------------

class sftp_channel : public channel
{
  public:
	sftp_channel(std::shared_ptr<basic_connection> connection);
	~sftp_channel();

	virtual void opened() override;
	virtual void closed() override;

	template <typename Handler>
	auto async_init(int version, Handler &&handler)
	{
		return boost::asio::async_initiate<Handler, void(boost::system::error_code, int)>(
			async_sftp_init_impl{}, handler, this, version);
	}

	template <typename Handler>
	auto read_dir(const std::string &path, Handler &&handler)
	{
		return boost::asio::async_initiate<Handler, void(boost::system::error_code, std::list<std::tuple<std::string, std::string, pinch::file_attributes>>)>(
			async_readdir_impl{}, handler, this, m_request_id++, path);
	}

	//	template<typename Handler>
	//	void			read_file(const std::string& path, Handler&& handler);
	//
	//	template<typename Handler>
	//	void			write_file(const std::string& path, Handler&& handler);

  private:
	virtual void receive_data(const char *data, size_t size) override;
	void process_packet();

	void write(opacket &&out)
	{
		opacket p = opacket() << std::move(out);
		send_data(std::move(p));
	}

	uint32_t m_request_id;
	uint32_t m_version;
	ipacket m_packet;

	std::list<detail::sftp_operation *> m_sftp_ops;

	template <typename OpHandler = detail::sftp_operation>
	OpHandler *fetch_op(uint32_t id)
	{
		for (auto op : m_sftp_ops)
		{
			if (op->m_id != id)
				continue;

			return dynamic_cast<OpHandler *>(op);
		}

		return nullptr;
	}

	// --------------------------------------------------------------------

	struct async_sftp_init_impl
	{
		template <typename Handler>
		void operator()(Handler &&handler, sftp_channel *ch, int version)
		{
			ch->do_init(std::unique_ptr<detail::sftp_init_op>(new detail::sftp_init_handler(std::move(handler), ch->get_executor(), version)));
		}
	};

	struct async_readdir_impl
	{
		template <typename Handler>
		void operator()(Handler &&handler, sftp_channel *ch, uint32_t request_id, const std::string &path)
		{
			ch->do_readdir(std::unique_ptr<detail::sftp_readdir_op>(new detail::sftp_readdir_handler(std::move(handler), ch->get_executor(), request_id, path)));
		}
	};

  private:
	friend struct async_sftp_init_impl;

	void do_init(std::unique_ptr<detail::sftp_init_op> op);
	void do_readdir(std::unique_ptr<detail::sftp_readdir_op> op);

	std::unique_ptr<detail::sftp_init_op> m_init_op;
};

} // namespace pinch

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
