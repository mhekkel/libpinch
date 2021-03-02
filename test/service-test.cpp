//#define BOOST_ASIO_ENABLE_HANDLER_TRACKING

#include <boost/asio.hpp>

#include <iostream>
#include <deque>

#include <type_traits>

#include <boost/algorithm/string.hpp>
#include <boost/iostreams/filtering_stream.hpp>

#include "pinch/connection.hpp"
#include "pinch/connection_pool.hpp"
#include "pinch/channel.hpp"
#include "pinch/terminal_channel.hpp"
#include "pinch/ssh_agent.hpp"
#include "pinch/crypto-engine.hpp"


namespace ba = boost::algorithm;
namespace io = boost::iostreams;

int main() {
	using boost::asio::ip::tcp;

	boost::asio::io_context io_context;

	auto conn = std::make_shared<pinch::connection>(io_context, "maarten");

	tcp::resolver resolver(io_context);
	tcp::resolver::results_type endpoints = resolver.resolve("localhost", "2022");

	boost::asio::connect(conn->lowest_layer(), endpoints);

	// conn->async_connect([](const boost::system::error_code& ec)
	// {
	// 	std::cout << "handler, ec = " << ec.message() << std::endl;
	// 	// t->close();
	// });

	auto channel = std::make_shared<pinch::channel>(conn);

	channel->async_open([](const boost::system::error_code& ec)
	{
		std::cout << "handler, ec = " << ec.message() << std::endl;
		// t->close();
	});


	io_context.run();

	return 0;
}
