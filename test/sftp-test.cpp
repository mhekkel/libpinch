//        Copyright Maarten L. Hekkelman 2013-2021
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)


#include "pinch.hpp"

#include <iostream>

#if defined(_MSC_VER)
#pragma comment(lib, "libz")
#pragma comment(lib, "libpinch")
#pragma comment(lib, "cryptlib")
#endif

class client
{
  public:
	client(std::shared_ptr<pinch::basic_connection> connection)
		: m_first(true)
	{
		m_channel.reset(new pinch::terminal_channel(connection));
		m_channel->open_with_pty(80, 24, "xterm", true, true, "", [this](const asio_system_ns::error_code &ec) {
			if (ec)
			{
				std::cerr << "error opening channel: " << ec.message() << std::endl;
				m_channel->close();
			}
			else
				this->received(ec, 0);
		});

		m_sftp_channel.reset(new pinch::sftp_channel(connection));
		m_sftp_channel->async_init(3, [this](const asio_system_ns::error_code &ec, int version) {
			if (ec or version != 3)
			{
				std::cerr << "error sftp opening channel: " << ec.message() << std::endl;
				m_sftp_channel->close();
			}
			else
			{
				m_sftp_channel->read_dir("/home/maarten",
					[](const asio_system_ns::error_code &ec, const std::list<std::tuple<std::string, std::string, pinch::file_attributes>> &files) {
						if (ec)
							std::cerr << "read dir error: " << ec.message() << std::endl;
						else
						{
							for (const auto &[name, longname, attr] : files)
								std::cout << longname << std::endl;
						}
					});
			}
		});
	}

	void written(const asio_system_ns::error_code &ec, std::size_t bytes_received)
	{
		if (ec)
		{
			std::cerr << "error writing channel: " << ec.message() << std::endl;
			m_channel->close();
		}
	}

	void received(const asio_system_ns::error_code &ec, std::size_t bytes_received)
	{
		if (ec)
		{
			std::cerr << std::endl
					  << "error reading channel: " << ec.message() << std::endl
					  << std::endl;
			m_channel->close();
		}
		else
		{
			if (bytes_received > 0 and m_first)
			{
				////						const char k_cmd[] = "ssh-add -L\n";
				////						const char k_cmd[] = "ssh www\n";
				//						const char k_cmd[] = "xclock\n";
				//						asio_ns::const_buffers_1 b(k_cmd, strlen(k_cmd));
				//
				//						asio_ns::async_write(m_channel, b, [this](const asio_system_ns::error_code& ec, size_t bytes_transferred)
				//						{
				//							this->written(ec, bytes_transferred);
				//						});

				m_first = false;
			}

			std::istream in(&m_response);
			std::cout << in.rdbuf();

			asio_ns::async_read(*m_channel, m_response,
				asio_ns::transfer_at_least(1),
				[this](const asio_system_ns::error_code &ec, size_t bytes_transferred) {
					this->received(ec, bytes_transferred);
				});
		}
	}

	std::shared_ptr<pinch::terminal_channel> m_channel;
	std::shared_ptr<pinch::sftp_channel> m_sftp_channel;
	asio_ns::streambuf m_response;
	bool m_first;
};

int main(int argc, char *const argv[])
{
	try
	{
		if (argc != 4)
		{
			std::cerr << "usage: test <host> <port> <user>" << std::endl;
			return 1;
		}

		std::string host = argv[1];
		std::string port = argv[2];
		std::string user = argv[3];

		asio_ns::io_context io_context;
		pinch::connection_pool pool(io_context);

		std::shared_ptr<pinch::basic_connection> connection(pool.get(user, host, std::stoi(port)));

		connection->set_accept_host_key_handler(
			[](const std::string &host_name, const std::string &algorithm, const pinch::blob &key, pinch::host_key_state state) {
				std::cout << "validating " << host_name << " with algo " << algorithm << std::endl
						  << "  ==> in thread 0x" << std::hex << std::this_thread::get_id() << std::endl;
				return pinch::host_key_reply::trust_once;
			});

		client *c = nullptr;

		//		connection.async_connect([&connection, &c](const asio_system_ns::error_code& ec)
		//		{
		//			if (ec)
		//			{
		//				cerr << "error connecting: " << ec.message() << endl;
		//				exit(1);
		//			}

		c = new client(connection);
		//		});

		asio_ns::signal_set sigset(io_context, SIGHUP, SIGINT);
		sigset.async_wait([&io_context](asio_system_ns::error_code, int signal) { io_context.stop(); });

		io_context.run();
	}
	catch (std::exception &e)
	{
		std::cerr << "exception: " << e.what() << std::endl;
	}

	return 0;
}
