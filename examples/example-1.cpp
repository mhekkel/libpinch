#include <iostream>

#include <pinch/connection_pool.hpp>

int main()
{
	boost::asio::io_context io_context;

	pinch::connection_pool pool(io_context);

	auto connection = pool.get("maarten", "s4");

	connection->set_provide_password_callback([]() { return "tiger"; });
	connection->set_always_accept_host_key_once();

	auto channel = std::make_shared<pinch::exec_channel>(connection, "uptime",
		[connection](const std::string& req, int status)
		{
			std::cout << "req: " << req << " -> status: " << status << std::endl;
			connection->close();
		}, io_context.get_executor());

	channel->async_open([](boost::system::error_code ec)
	{
		std::cout << "open result: " << ec.message() << std::endl;
	});

	io_context.run();

	return 0;
}