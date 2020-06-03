#include <assh/connection.hpp>

// --------------------------------------------------------------------

int main()
{
	boost::asio::io_service io_service;

	auto c = new assh::connection(io_service, "maarten", "localhost", 22);


	io_service.run();

	return 0;
}