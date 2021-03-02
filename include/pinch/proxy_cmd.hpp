// //           Copyright Maarten L. Hekkelman 2013
// // Distributed under the Boost Software License, Version 1.0.
// //    (See accompanying file LICENSE_1_0.txt or copy at
// //          http://www.boost.org/LICENSE_1_0.txt)

// #pragma once

// #include <pinch/pinch.hpp>
// #include <pinch/connection.hpp>

// namespace pinch
// {

// 	class proxy_channel;

// 	class proxied_connection : public connection_base
// 	{
// 	public:
// 		proxied_connection(std::shared_ptr<connection_base> proxy,
// 						   const std::string &nc_cmd,
// 						   const std::string &user,
// 						   const std::string &host, int16_t port = 22);

// 		~proxied_connection();

// 		boost::asio::io_service &
// 		get_io_service()
// 		{
// 			return m_proxy->get_io_service();
// 		}

// 		virtual void set_validate_callback(const validate_callback_type &cb);

// 		virtual std::shared_ptr<connection_base> get_proxy() const
// 		{
// 			return m_proxy;
// 		}

// 	protected:
// 		virtual void start_handshake();

// 		virtual bool validate_host_key(const std::string &pk_alg, const std::vector<uint8_t> &host_key);

// 		virtual void async_write_int(boost::asio::streambuf *request, basic_write_op *op);
// 		virtual void async_read_version_string();
// 		virtual void async_read(uint32_t at_least);

// 	private:
// 		std::shared_ptr<connection_base> m_proxy;
// 		std::shared_ptr<proxy_channel> m_channel;
// 		std::string m_host;
// 	};

// } // namespace pinch
