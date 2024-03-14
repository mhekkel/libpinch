//[ first_example 
#include <iostream>

#include "pinch/connection_pool.hpp"

int main(int argc, char* const argv[])
{
	if (argc != 3)
	{
		std::cerr << "usage: example-1 username host\n";
		exit(1);
	}

	/*<< We must provide an io_context to the connection_pool >>*/
	asio_ns::io_context io_context;

	/*<< Setup a connection pool >>*/
	pinch::connection_pool pool(io_context);

	/*<< Open, or reuse a connection to user @ host >>*/
	auto connection = pool.get(argv[1], argv[2]);

	/*<< This sample password providing routine should of course be updated to no longer echo the password >>*/
	connection->set_provide_password_callback([]()
	{
		std::cout << "password: "; std::cout.flush();
		std::string password;
		std::cin >> password;
		return password;
	});

	/*<< Always accept the host key >>*/
	connection->set_always_accept_host_key_once();

	/*<< Create an execution channel with the command 'uptime' >>*/
	auto channel = std::make_shared<pinch::exec_channel>(connection, "uptime",
		[connection](const std::string& req, int status)
		{
			std::cout << "req: " << req << " -> status: " << status << '\n';
			connection->close();
		}, io_context.get_executor());

	/*<< Open a execution channel with the command 'uptime' >>*/
	channel->async_open([](asio_system_ns::error_code ec)
	{
		std::cout << "open result: " << ec.message() << '\n';
	});

	/*<< Run the io_context >>*/
	io_context.run();

	return 0;
}
//]