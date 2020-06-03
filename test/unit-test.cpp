#include <iostream>

#include <assh/connection_pool.hpp>
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

	assh::connection_pool pool(io_service);

	auto connection = pool.get("maarten", "localhost", 22);

	connection->set_password_callback([connection]()
	{
		std::string password;

		std::cout << "password: "; std::cout.flush(); SetStdinEcho(false);
		std::getline(std::cin, password);
		std::cout << std::endl;
		if (password.empty())
			connection->disconnect();
		else
			connection->response({ password });
	});

	auto ch = std::make_shared<assh::terminal_channel>(connection);

	ch->open_with_pty(80, 24, "xterm", false, false, "", [ch, connection](boost::system::error_code ec) {
		std::cout << ec.message() << std::endl;

		connection->disconnect();
	});

	io_service.run();

	return 0;
}