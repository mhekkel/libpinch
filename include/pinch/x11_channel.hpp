// //           Copyright Maarten L. Hekkelman 2013
// // Distributed under the Boost Software License, Version 1.0.
// //    (See accompanying file LICENSE_1_0.txt or copy at
// //          http://www.boost.org/LICENSE_1_0.txt)

// #pragma once

// #include <pinch/pinch.hpp>

// #include <boost/format.hpp>
// #include <boost/function.hpp>
// #include <boost/asio.hpp>

// #include <pinch/channel.hpp>
// #include <pinch/packet.hpp>

// namespace pinch
// {

// 	// --------------------------------------------------------------------

// 	struct x11_socket_impl_base;

// 	class x11_channel : public channel
// 	{
// 	public:
// 		x11_channel(std::shared_ptr<connection_base> inConnection);
// 		~x11_channel();

// 		void receive_raw(const boost::system::error_code &ec, std::size_t bytes_received);

// 	protected:
// 		virtual void opened();
// 		virtual void closed();

// 		virtual void receive_data(const char *data, std::size_t size);
// 		bool check_validation();

// 		std::unique_ptr<x11_socket_impl_base>
// 			m_impl;
// 		bool m_verified;
// 		std::string m_auth_protocol, m_auth_data;
// 		std::vector<uint8_t> m_packet;
// 		boost::asio::streambuf m_response;
// 	};

// } // namespace pinch
