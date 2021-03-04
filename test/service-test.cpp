//#define BOOST_ASIO_ENABLE_HANDLER_TRACKING

#include <boost/asio.hpp>

#include <iostream>
#include <deque>

#include <type_traits>

#include <boost/algorithm/string.hpp>
#include <boost/iostreams/filtering_stream.hpp>
#include <boost/iostreams/copy.hpp>

#include "pinch/connection.hpp"
#include "pinch/connection_pool.hpp"
#include "pinch/channel.hpp"
#include "pinch/terminal_channel.hpp"
#include "pinch/ssh_agent.hpp"
#include "pinch/crypto-engine.hpp"

namespace ba = boost::algorithm;
namespace io = boost::iostreams;

boost::asio::streambuf buffer;

void read_from_channel(pinch::channel_ptr ch, int start = 1)
{
	boost::asio::async_read(*ch, buffer, boost::asio::transfer_at_least(1),
	[
		ch, start
	]
	(const boost::system::error_code& ec, std::size_t bytes_transferred) mutable
	{
		if (ec)
			std::cerr << ec.message() << std::endl;
		else
		{
			std::istream in(&buffer);
			io::copy(in, std::cout);

			read_from_channel(ch, 0);

			if (start)
			{
				ch->send_data("xterm\n");
			}
		}
	});
}


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

	// auto proxied_conn = std::make_shared<pinch::proxied_connection>(conn, "/bin/netcat %h %p", "maarten", "localhost", 2021);
	auto proxied_conn = std::make_shared<pinch::proxied_connection>(conn, "maarten", "localhost", 2021);

	auto channel = std::make_shared<pinch::terminal_channel>(proxied_conn);
	// auto channel = std::make_shared<pinch::terminal_channel>(conn);

	auto msg = [](const std::string& msg, const std::string& lang)
	{
		std::cout << "Mesage callback, msg = " << msg << ", lang = " << lang << std::endl;
	};

	channel->set_message_callbacks(
		msg, msg, msg
	);

	channel->open_with_pty(80, 24, "vt220", true, true, "",
		[t = channel](const boost::system::error_code& ec)
	{
		std::cout << "handler, ec = " << ec.message() << std::endl;
		
		read_from_channel(t);
	});


	io_context.run();

	return 0;
}
