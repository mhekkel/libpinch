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

//void test_packet()
//{
//	assh::opacket p(assh::userauth_request);
//	p << "maarten" << "" << "password" << (uint8)1 << (uint16)2 << (uint32)3 << (uint64)4;
//	
//	vector<boost::asio::const_buffer> buffers;
//	
//	p.to_buffers(8, buffers);
//
//	cout << buffers << endl;
//
//	string s1, s2, s3;
//	uint8 i1;
//	uint16 i2;
//	uint32 i3;
//	uint64 i4;
//	
//	p >> s1 >> s2 >> s3 >> i1 >> i2 >> i3 >> i4;
//	
//	cout << s1 << endl
//		 << s2 << endl
//		 << s3 << endl
//		 << int(i1) << endl
//		 << i2 << endl
//		 << i3 << endl
//		 << i4 << endl;
//}

void foo(const boost::system::error_code& ec)
{
	if (ec)
		cout << ec << endl;
	else
		cout << "Yeah!" << endl;
}

int main(int argc, char* const argv[])
{
	try
	{
		if (argc != 3)
		{
			cerr << "usage: test <host> <port>" << endl;
			return 1;
		}
		
		boost::asio::io_service io_service;
	
		boost::asio::ip::tcp::resolver resolver(io_service);
		boost::asio::ip::tcp::resolver::query query(argv[1], argv[2]);
		boost::asio::ip::tcp::resolver::iterator iterator = resolver.resolve(query);
		
		boost::asio::ip::tcp::socket socket(io_service);
		boost::asio::connect(socket, iterator);
		
		assh::connection c(socket);
		
		

		c.async_connect("maarten", [](const boost::system::error_code& ec)
		{
			if (ec)
				cout << ec << endl;
			else
				cout << "Yeah!" << endl;	
		});


		io_service.run();
		
		
	}
	catch (exception& e)
	{
		cerr << "exception: " << e.what() << endl;
	}

	return 0;
}
