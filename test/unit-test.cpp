//        Copyright Maarten L. Hekkelman 2013-2021
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

// #define BOOST_ASIO_ENABLE_HANDLER_TRACKING

#include <iostream>

#include <pinch/connection.hpp>
#include <pinch/terminal_channel.hpp>

void SetStdinEcho(bool enable)
{
	struct termios tty;
	::tcgetattr(STDIN_FILENO, &tty);
	if(not enable)
		tty.c_lflag &= ~ECHO;
	else
		tty.c_lflag |= ECHO;

	(void)::tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}

// // --------------------------------------------------------------------

// int main()
// {
// 	boost::asio::io_service io_service;

// 	// auto connection = std::make_shared<pinch::connection>(io_service, "maarten", "localhost", 22);

// 	// connection->set_provide_credentials_callback([connection]()
// 	// {
// 	// 	std::string password;

// 	// 	std::cout << "password: "; std::cout.flush();	SetStdinEcho(false);
// 	// 	std::getline(std::cin, password);				SetStdinEcho(true);
// 	// 	std::cout << std::endl;

// 	// 	if (password.empty())
// 	// 		connection->close();
// 	// 	else
// 	// 		connection->response({ password });
// 	// });

// 	// auto ch = std::make_shared<pinch::terminal_channel>(connection);

// 	// auto mcb = [](const std::string& msg, const std::string& lang)
// 	// {
// 	// 	std::cout << msg << " (" << lang << ')' << std::endl;
// 	// };

// 	// ch->set_message_callbacks(mcb, mcb, mcb);

// 	// ch->open_with_pty(80, 24, "xterm", false, false, "", [ch, connection](boost::system::error_code ec) {
// 	// 	std::cout << ec.message() << std::endl;

// 	// 	connection->close();
// 	// });

//     auto work = boost::asio::make_work_guard(io_service);
    
// 	std::thread t([&io_service]() {
// 		io_service.run();
// 	});

// 	auto connection = std::make_shared<pinch::connection2>(io_service, "maarten", "localhost", 2022);
	
// 	auto f1 = connection->async_connect(boost::asio::use_future);

// 	try
// 	{
// 		f1.get();
// 	}
// 	catch (const std::exception& e)
// 	{
// 		std::cerr << e.what() << std::endl;
// 	}

// 	// auto f2 = connection->async_authenticate(boost::asio::use_future);

// 	// try
// 	// {
// 	// 	f2.get();
// 	// }
// 	// catch (const std::exception& e)
// 	// {
// 	// 	std::cerr << e.what() << std::endl;
// 	// }

// 	io_service.stop();
// 	t.join();

// 	return 0;
// }


// --------------------------------------------------------------------


void handler(const boost::system::error_code& error, int n)
{
	if (error)
		std::cout << error.message() << std::endl;
	else
		std::cout << "expired " << n << std::endl;
}

template<typename CompletionToken>
auto async_wait2(std::future<void>& a, CompletionToken&& token)
{
	return boost::asio::async_completion<CompletionToken, void(boost::system::error_code)>(
		
	);
}

class seq_timed
{
  public:

	seq_timed(boost::asio::io_context& io_context)
		: m_strand(io_context.get_executor())
	{
		
	}

	template<typename CompletionToken>
	auto async_wait_for(int secs, CompletionToken&& token)
	{
		
	}


  private:

	boost::asio::strand<boost::asio::io_context::executor_type> m_strand;

};



int main()
{

	boost::asio::io_context io_context;

	boost::asio::strand<boost::asio::io_context::executor_type> strand(io_context.get_executor());

	// boost::asio::deadline_timer timer(strand.context());
	boost::asio::deadline_timer timer(strand);

	// Construct a timer with an absolute expiry time.
	timer.expires_from_now(boost::posix_time::seconds(5));

	// Start an asynchronous wait.
	timer.async_wait(std::bind(handler, std::placeholders::_1, 1));

	// boost::asio::deadline_timer timer(strand.context());
	boost::asio::deadline_timer timer2(strand);

	// Construct a timer with an absolute expiry time.
	timer2.expires_from_now(boost::posix_time::seconds(1));

	// Start an asynchronous wait.
	timer2.async_wait(std::bind(handler, std::placeholders::_1, 2));


	io_context.run();

	return 0;
}
