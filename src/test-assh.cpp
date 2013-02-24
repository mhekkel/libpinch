#include <assh/config.hpp>

#include <iostream>

#include <boost/foreach.hpp>
#define foreach BOOST_FOREACH
#include <boost/bind.hpp>
#include <boost/iostreams/copy.hpp>

#include <assh/connection.hpp>
#include <assh/terminal_channel.hpp>
#include <assh/debug.hpp>

#if defined(_MSC_VER)
//#pragma comment (lib, "libzeep")
#pragma comment (lib, "libassh")
#pragma comment (lib, "cryptlib")
#endif

using namespace std;
namespace io = boost::iostreams;

class client
{
  public:
			client(assh::connection& connection)
				: m_channel(connection)
				, m_first(true)
			{
				m_channel.open_with_pty(80, 24, "vt220", true, true, [this](const boost::system::error_code& ec)
				{
					if (ec)
					{
						cerr << "error opening channel: " << ec.message() << endl;
						m_channel.close();
					}
					else
						this->received(ec, 0);
				});
			}
	
	void	written(const boost::system::error_code& ec, std::size_t bytes_received)
			{
				if (ec)
				{
					cerr << "error writing channel: " << ec.message() << endl;
					m_channel.close();
				}
			}
	
	void	received(const boost::system::error_code& ec, std::size_t bytes_received)
			{
				if (ec)
				{
					cerr << endl
						 << "error reading channel: " << ec.message() << endl
						 << endl;
					m_channel.close();
				}
				else
				{
					if (bytes_received > 0 and m_first)
					{
						const char k_cmd[] = "ssh-add -L\n";
						boost::asio::const_buffers_1 b(k_cmd, strlen(k_cmd));
					
						boost::asio::async_write(m_channel, b, [this](const boost::system::error_code& ec, size_t bytes_transferred)
						{
							this->written(ec, bytes_transferred);
						});
					
						m_first = false;
					}

					istream in(&m_response);
					io::copy(in, cout);
				
					boost::asio::async_read(m_channel, m_response,
						boost::asio::transfer_at_least(1),
						[this](const boost::system::error_code& ec, size_t bytes_transferred)
					{
						this->received(ec, bytes_transferred);
					});
				}
			}
	
	assh::terminal_channel	m_channel;
	boost::asio::streambuf	m_response;
	bool					m_first;
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
	
		boost::asio::io_service io_service;
		boost::asio::ip::tcp::resolver resolver(io_service);
		boost::asio::ip::tcp::resolver::query query(argv[1], argv[2]);
		boost::asio::ip::tcp::resolver::iterator iterator = resolver.resolve(query);
		
		boost::asio::ip::tcp::socket socket(io_service);
		boost::asio::connect(socket, iterator);

		string user = argv[3];
		
		assh::connection connection(socket, user);
		
		client* c = nullptr;
		
		connection.async_connect([&c, &connection](const boost::system::error_code& ec)
		{
			if (ec)
			{
				cerr << "error connecting: " << ec.message() << endl;
				exit(1);
			}

			c = new client(connection);
		});
				
		io_service.run();
		
		delete c;
	}
	catch (exception& e)
	{
		cerr << "exception: " << e.what() << endl;
	}

	return 0;
}
