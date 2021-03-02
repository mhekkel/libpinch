#include <pinch/pinch.hpp>

#include <iostream>

#include <boost/bind.hpp>
#include <boost/iostreams/copy.hpp>
#include <boost/lexical_cast.hpp>

#include <pinch/connection.hpp>
#include <pinch/connection_pool.hpp>
#include <pinch/proxy_cmd.hpp>
#include <pinch/terminal_channel.hpp>
#include <pinch/sftp_channel.hpp>
#include <pinch/debug.hpp>

#if defined(_MSC_VER)
#pragma comment (lib, "libz")
#pragma comment (lib, "libpinch")
#pragma comment (lib, "cryptlib")
#endif

using namespace std;
namespace io = boost::iostreams;

class client
{
  public:
			client(pinch::std::shared_ptr<connection_base> connection)
				: m_first(true)
			{
				m_channel.reset(new pinch::terminal_channel(connection));
				m_channel->open_with_pty(80, 24, "xterm", true, true, [this](const boost::system::error_code& ec)
				{
					if (ec)
					{
						cerr << "error opening channel: " << ec.message() << endl;
						m_channel->close();
					}
					else
						this->received(ec, 0);
				});
				
				m_sftp_channel.reset(new pinch::sftp_channel(connection));
				m_sftp_channel->async_open([this](const boost::system::error_code& ec)
				{
					if (ec)
					{
						cerr << "error sftp opening channel: " << ec.message() << endl;
						m_sftp_channel->close();
					}
					else
					{
						m_sftp_channel->read_dir("/home/maarten", boost::bind(&client::read_dir, this, _1, _2, _3, _4));

						//m_sftp_channel.read_dir("/home/maarten", []
						//		(const boost::system::error_code& ec, const string& name, const string& longname,
						//			const pinch::sftp_channel::file_attributes& attr) -> bool
						//		{
						//			if (ec)
						//				cerr << "read dir error: " << ec.message() << endl;
						//			else
						//				cout << longname << endl;
						//			return true;
						//		});
					}
				});
			}

	bool	read_dir(const boost::system::error_code& ec, const string& name, const string& longname,
				const pinch::sftp_channel::file_attributes& attr)
			{
				if (ec)
					cerr << "read dir error: " << ec.message() << endl;
				else
					cout << longname << endl;
				return true;
			}
	
	void	written(const boost::system::error_code& ec, std::size_t bytes_received)
			{
				if (ec)
				{
					cerr << "error writing channel: " << ec.message() << endl;
					m_channel->close();
				}
			}
	
	void	received(const boost::system::error_code& ec, std::size_t bytes_received)
			{
				if (ec)
				{
					cerr << endl
						 << "error reading channel: " << ec.message() << endl
						 << endl;
					m_channel->close();
				}
				else
				{
					if (bytes_received > 0 and m_first)
					{
////						const char k_cmd[] = "ssh-add -L\n";
////						const char k_cmd[] = "ssh www\n";
//						const char k_cmd[] = "xclock\n";
//						boost::asio::const_buffers_1 b(k_cmd, strlen(k_cmd));
//					
//						boost::asio::async_write(m_channel, b, [this](const boost::system::error_code& ec, size_t bytes_transferred)
//						{
//							this->written(ec, bytes_transferred);
//						});
					
						m_first = false;
					}

					istream in(&m_response);
					io::copy(in, cout);
				
					boost::asio::async_read(*m_channel, m_response,
						boost::asio::transfer_at_least(1),
						[this](const boost::system::error_code& ec, size_t bytes_transferred)
					{
						this->received(ec, bytes_transferred);
					});
				}
			}
	
	shared_ptr<pinch::terminal_channel> m_channel;
	shared_ptr<pinch::sftp_channel> m_sftp_channel;
	boost::asio::streambuf m_response;
	bool m_first;
};

int main(int argc, char* const argv[])
{
	try
	{
		if (argc != 4)
		{
			cerr << "usage: test <host> <port> <user>" << endl;
			return 1;
		}
		
		string host = argv[1];
		string port = argv[2];
		string user = argv[3];
	
		boost::asio::io_service io_service;
		pinch::connection_pool pool(io_service);

		//pool.register_proxy("newcmbi2", 22, "/usr/bin/nc %h %p", "maarten", "www", 22);
		//pool.register_proxy("newcmbi2.cmbi.ru.nl", 22, "/usr/bin/nc %h %p", "maarten", "www", 22);
	
		pinch::std::shared_ptr<connection_base> connection(pool.get(user, host, boost::lexical_cast<int16_t>(port)));

		client* c = nullptr;
		
//		connection.async_connect([&connection, &c](const boost::system::error_code& ec)
//		{
//			if (ec)
//			{
//				cerr << "error connecting: " << ec.message() << endl;
//				exit(1);
//			}
			
			c = new client(connection);
//		});
				
		io_service.run();
	}
	catch (exception& e)
	{
		cerr << "exception: " << e.what() << endl;
	}

	return 0;
}
