//        Copyright Maarten L. Hekkelman 2013-2021
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#define BOOST_ASIO_ENABLE_HANDLER_TRACKING

#include "pinch.hpp"

#include <iostream>
#include <thread>

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

// --------------------------------------------------------------------

void handler(const asio_system_ns::error_code& error, int n)
{
	if (error)
		std::cout << error.message() << std::endl;
	else
		std::cout << "expired " << n << std::endl;
}

template<typename CompletionToken>
auto async_wait2(std::future<void>& a, CompletionToken&& token)
{
	return asio_ns::async_completion<CompletionToken, void(asio_system_ns::error_code)>(
		
	);
}

class seq_timed
{
  public:

	seq_timed(asio_ns::io_context& io_context)
		: m_strand(io_context.get_executor())
	{
		
	}

	template<typename CompletionToken>
	auto async_wait_for(int secs, CompletionToken&& token)
	{
		
	}


  private:

	asio_ns::strand<asio_ns::io_context::executor_type> m_strand;

};

int main()
{

	asio_ns::io_context io_context;

	asio_ns::strand<asio_ns::io_context::executor_type> strand(io_context.get_executor());

	// asio_ns::deadline_timer timer(strand.context());
	asio_ns::deadline_timer timer(strand);

	// Construct a timer with an absolute expiry time.
	timer.expires_from_now(boost::posix_time::seconds(3));

	// Start an asynchronous wait.
	timer.async_wait(std::bind(handler, std::placeholders::_1, 1));

	// asio_ns::deadline_timer timer(strand.context());
	asio_ns::deadline_timer timer2(strand);

	// Construct a timer with an absolute expiry time.
	timer2.expires_from_now(boost::posix_time::seconds(1));

	// Start an asynchronous wait.
	timer2.async_wait(std::bind(handler, std::placeholders::_1, 2));


	io_context.run();

	return 0;
}
