#define BOOST_ASIO_ENABLE_HANDLER_TRACKING

#include <boost/asio.hpp>

#include <iostream>
#include <deque>

#include "assh/connection.hpp"
#include "assh/connection_pool.hpp"
#include "assh/channel.hpp"
#include "assh/terminal_channel.hpp"

namespace assh
{

template<typename Stream>
class connection2
{
  public:

	template<typename Arg>
	connection2(Arg&& arg)
		: m_next_layer(std::forward<Arg>(arg))
	{

	}

  private:
	Stream m_next_layer;
};

}



int main() {

	boost::asio::io_context io_context;

	// auto c = std::make_shared<assh::connection>(io_context, "maarten", "localhost", 22);

	assh::connection_pool pool(io_context);

	auto c = pool.get("maarten", "localhost", 2022);

	auto t = std::make_shared<assh::terminal_channel>(c);

	auto handler = [](const std::string& a, const std::string& b)
	{
		std::cout << a << b << std::endl;
	};

	t->set_message_callbacks(handler, handler, handler);

	t->open_with_pty(80, 24, "vt220", false, false, "/bin/ls",
		[t](const boost::system::error_code& ec)
		{
			std::cout << "handler, ec = " << ec.message() << std::endl;
			t->close();
		});

	io_context.run();

	return 0;
}