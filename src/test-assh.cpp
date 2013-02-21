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
			client(boost::asio::ip::tcp::socket& socket, const string& user)
				: m_connection(socket, user)
				, m_channel(nullptr)
			{
				m_connection.async_connect(user, [this](const boost::system::error_code& ec)
				{
					if (ec)
					{
						cerr << "error connecting: " << ec.message() << endl;
						exit(1);
					}

					this->open_terminal();
				});
			}
	
	void	open_terminal()
			{
				m_channel = new assh::terminal_channel(m_connection);
				m_channel->open([this](const boost::system::error_code& ec)
				{
					if (ec)
					{
						cerr << "error opening channel: " << ec.message() << endl;
						exit(1);
					}
					
					this->received(ec, 0);
				});
			}
	
	void	received(const boost::system::error_code& ec, std::size_t bytes_received)
			{
				if (ec)
				{
					cerr << endl
						 << "error reading channel: " << ec.message() << endl
						 << endl;
					exit(1);
				}

				istream in(&m_response);
				io::copy(in, cout);
				
				auto cb = [this](const boost::system::error_code& ec, size_t bytes_transferred)
				{
					this->received(ec, bytes_transferred);
				};

				boost::asio::async_read(*m_channel, m_response, cb);
			}
	
	assh::connection		m_connection;
	assh::terminal_channel*	m_channel;
	boost::asio::io_service	m_io_service;
	boost::asio::streambuf	m_response;
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
		
		client ssh(socket, argv[3]);

		io_service.run();
	}
	catch (exception& e)
	{
		cerr << "exception: " << e.what() << endl;
	}

	return 0;
}
