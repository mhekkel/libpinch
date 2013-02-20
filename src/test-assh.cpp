#include <assh/config.hpp>

#include <iostream>

#include <boost/foreach.hpp>
#define foreach BOOST_FOREACH
#include <boost/bind.hpp>

#include <assh/connection.hpp>
#include <assh/debug.hpp>

#if defined(_MSC_VER)
//#pragma comment (lib, "libzeep")
#pragma comment (lib, "libassh")
#pragma comment (lib, "cryptlib")
#endif

using namespace std;

class client
{
  public:
			client(boost::asio::socket& socket, const string& user)
				: m_connection(socket, user)
			{
				m_connection.async_connect([](const boost::system::error_code& ec)
				{
					if (ec)
					{
						cerr << "Error: " << ec.message() << endl;
						exit(1);
					}

					received(ec, 0);	
				});
			}
	
	void	received(const boost::system::error_code& ec, std::size_t bytes_received)
			{
				if (ec)
				{
					cerr << endl
						 << "Error: " << ec.message() << endl
						 << endl;
					exit(1);
				}

				istream in(m_response);
				io::copy(in, cout);
				
				boost::asio::read_some(m_connection, m_response,
					boost::asio::transfer_at_least(1),
					boost::bind(&received, this, boost::asio::placeholders::error,
						boost::asio::placeholders::bytes_received));
			}
	
	connection				m_connection;
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
