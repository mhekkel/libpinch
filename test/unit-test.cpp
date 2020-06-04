#include <iostream>

#include <assh/connection.hpp>
#include <assh/terminal_channel.hpp>

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

int main()
{
	boost::asio::io_service io_service;

	// auto connection = std::make_shared<assh::connection>(io_service, "maarten", "localhost", 22);

	// connection->set_password_callback([connection]()
	// {
	// 	std::string password;

	// 	std::cout << "password: "; std::cout.flush();	SetStdinEcho(false);
	// 	std::getline(std::cin, password);				SetStdinEcho(true);
	// 	std::cout << std::endl;

	// 	if (password.empty())
	// 		connection->disconnect();
	// 	else
	// 		connection->response({ password });
	// });

	// auto ch = std::make_shared<assh::terminal_channel>(connection);

	// auto mcb = [](const std::string& msg, const std::string& lang)
	// {
	// 	std::cout << msg << " (" << lang << ')' << std::endl;
	// };

	// ch->set_message_callbacks(mcb, mcb, mcb);

	// ch->open_with_pty(80, 24, "xterm", false, false, "", [ch, connection](boost::system::error_code ec) {
	// 	std::cout << ec.message() << std::endl;

	// 	connection->disconnect();
	// });

    auto work = boost::asio::make_work_guard(io_service);
    
	std::thread t([&io_service]() {
		io_service.run();
	});

	auto connection = std::make_shared<assh::connection2>(io_service, "maarten", "localhost", 2022);
	
	auto f1 = connection->async_connect(boost::asio::use_future);

	try
	{
		f1.get();
	}
	catch (const std::exception& e)
	{
		std::cerr << e.what() << std::endl;
	}

	auto f2 = connection->async_authenticate(boost::asio::use_future);

	try
	{
		f2.get();
	}
	catch (const std::exception& e)
	{
		std::cerr << e.what() << std::endl;
	}

	io_service.stop();
	t.join();

	return 0;
}