// //           Copyright Maarten L. Hekkelman 2013
// // Distributed under the Boost Software License, Version 1.0.
// //    (See accompanying file LICENSE_1_0.txt or copy at
// //          http://www.boost.org/LICENSE_1_0.txt)

// #pragma once

// #include <assh/config.hpp>

// #include <boost/asio.hpp>

// #include <assh/channel.hpp>
// #include <assh/packet.hpp>

// namespace assh
// {

// class connection_base;

// class port_forward_listener
// {
//   public:
// 	port_forward_listener(std::shared_ptr<connection_base> connection);
// 	~port_forward_listener();

// 	void forward_port(
// 		const std::string& local_addr, int16_t local_port,
// 		const std::string& remote_addr, int16_t remote_port);
// 	void forward_socks5(const std::string& local_addr, int16_t local_port);

// 	void remove_port_forward(int16_t local_port);
// 	void connection_closed();

// 	//void accept_failed(const boost::system::error_code& ec, bound_port* e);

//   private:
// 	port_forward_listener(const port_forward_listener&);
// 	port_forward_listener&
// 		operator=(const port_forward_listener&);

// 	//typedef std::list<bound_port*> bound_port_list;

// 	std::shared_ptr<connection_base> m_connection;
// 	//bound_port_list m_bound_ports;
// };

// // --------------------------------------------------------------------

// class forwarding_channel : public channel
// {
//   public:
// 	forwarding_channel(std::shared_ptr<connection_base> inConnection, const std::string& remote_addr, int16_t remote_port);

// 	virtual std::string channel_type() const		{ return "direct-tcpip"; }
// 	virtual void fill_open_opacket(opacket& out);

// 	bool forwards_to(const std::string& host, int16_t port) const
// 	{
// 		return port == m_remote_port and host == m_remote_address;
// 	}

//   protected:
// 	std::string m_remote_address;
// 	int16_t m_remote_port;
// };

// }
