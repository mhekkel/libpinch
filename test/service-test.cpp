//        Copyright Maarten L. Hekkelman 2013-2021
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#define BOOST_ASIO_ENABLE_HANDLER_TRACKING

#include "pinch.hpp"

#include <deque>
#include <iostream>
#include <map>
#include <thread>
#include <type_traits>

// --------------------------------------------------------------------

#if __has_include(<unistd.h>)

#include <termios.h>
#include <unistd.h>

void SetStdinEcho(bool enable = true)
{
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    if( !enable )
        tty.c_lflag &= ~ECHO;
    else
        tty.c_lflag |= ECHO;

    (void) tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}

#else
#include <windows.h>

void SetStdinEcho(bool enable = true)
{
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE); 
    DWORD mode;
    GetConsoleMode(hStdin, &mode);

    if( !enable )
        mode &= ~ENABLE_ECHO_INPUT;
    else
        mode |= ENABLE_ECHO_INPUT;

    SetConsoleMode(hStdin, mode );
}

#endif


// --------------------------------------------------------------------

char this_thread_name()
{
	static std::mutex m_mutex;
	std::lock_guard lock(m_mutex);

	static std::map<std::thread::id,char> m_names;

	std::thread::id id = std::this_thread::get_id();

	auto i = m_names.find(id);
	if (i == m_names.end())
		return m_names[id] = 'A' + m_names.size();
	else
		return i->second;
}

// --------------------------------------------------------------------

class my_queue
{
  public:
	struct handler_base
	{
		virtual ~handler_base() = default;
		virtual void execute() = 0;
	};

	template <typename Handler>
	struct handler_impl : public handler_base
	{
		handler_impl(Handler &&handler)
			: m_handler(std::forward<Handler>(handler))
		{
		}

		void execute() override
		{
			m_handler();
		}

		Handler m_handler;
	};

	template <typename Handler>
	void submit(Handler &&handler)
	{
		std::lock_guard lock(m_mutex);
		m_q.emplace_back(new handler_impl<Handler>{std::move(handler)});
		m_cv.notify_one();
	}

	// void execute_one()
	// {
	// 	std::unique_lock lock(m_mutex);
	// 	m_cv.wait_for(lock, std::chrono::milliseconds(100));
	// 	if (not m_q.empty())
	// 	{
	// 		auto task = std::move(m_q.front());
	// 		m_q.pop_front();
	// 		lock.release();

	// 		task->execute();
	// 	}
	// }

	void stop()
	{
		m_stop = true;
	}

	void run()
	{
		std::cout << "Queue thread is " << this_thread_name() << std::endl;

		for (;;)
		{
			{
				std::unique_lock lock(m_mutex);
				m_cv.wait_for(lock, std::chrono::milliseconds(100));
			}

			if (m_stop)
				break;

			if (not m_q.empty())
			{
				auto task = std::move(m_q.front());
				m_q.pop_front();
				task->execute();
			}
		}
	}

	std::mutex m_mutex;
	std::condition_variable m_cv;
	std::deque<std::unique_ptr<handler_base>> m_q;
	bool m_stop = false;
};

class my_executor
{
  public:
	asio_ns::execution_context *m_context;
	my_queue *m_queue;

	bool operator==(const my_executor &other) const noexcept
	{
		return m_context == other.m_context;
	}

	bool operator!=(const my_executor &other) const noexcept
	{
		return !(*this == other);
	}

	asio_ns::execution_context &query(asio_ns::execution::context_t) const noexcept
	{
		return *m_context;
	}

	static constexpr asio_ns::execution::blocking_t::never_t query(
		asio_ns::execution::blocking_t) noexcept
	{
		// This executor always has blocking.never semantics.
		return asio_ns::execution::blocking.never;
	}

	template <class F>
	void execute(F &&f) const
	{
		m_queue->submit(std::move(f));
	}
};

asio_ns::streambuf buffer;

void read_from_channel(pinch::channel_ptr ch, int start = 1)
{
	asio_ns::async_read(*ch, buffer, asio_ns::transfer_at_least(1),
		[ch, start](const asio_system_ns::error_code &ec, std::size_t bytes_transferred) mutable {
			if (ec)
				std::cerr << ec.message() << std::endl;
			else
			{
				std::istream in(&buffer);
				std::cout << in.rdbuf();

				read_from_channel(ch, 0);

				if (start)
				{
					using namespace std::literals;
					ch->send_data("xterm\n"s);
				}
			}
		});
}

// --------------------------------------------------------------------

// attempt to fetch a result asynchronously

template <typename Handler, typename Executor>
bool async_validate(const std::string &host_name, const std::string &algorithm, const pinch::blob &key, Handler &&handler, Executor &executor)
{
	std::packaged_task<bool()> validate_task(
		[handler = std::move(handler), host_name, algorithm, key] { return handler(host_name, algorithm, key); });

	auto result = validate_task.get_future();

	asio_ns::dispatch(executor, [task = std::move(validate_task)]() mutable {
		task();
	});

	result.wait();

	return result.get();
}

// another attempt to fetch a result asynchronously

bool validate_host_key(const std::string &host, const std::string &algo, const pinch::blob &blob)
{
	std::cout << " validate_host_key in thread: " << this_thread_name()  << std::endl;
	return true;
}

template <typename Handler, typename Executor, typename... Args, typename Function>
auto async_val(Handler &&handler, Executor &executor, Function func, Args... args)
{
	using result_type = decltype(func(args...));

	enum state
	{
		start,
		running
	};

	std::packaged_task<result_type()> task(std::bind(func, args...));
	std::future<result_type> result = task.get_future();

	return asio_ns::async_compose<Handler, void(asio_system_ns::error_code, result_type)>(
		[task = std::move(task),
			result = std::move(result),
			state = start,
			executor](auto &self, asio_system_ns::error_code ec = {}, result_type r = {}) mutable {
			if (not ec)
			{
				if (state == start)
				{
					state = running;
					task();
					asio_ns::dispatch(executor, std::move(self));
					return;
				}

				try
				{
					r = result.get();
				}
				catch (...)
				{
					ec = pinch::error::make_error_code(pinch::error::host_key_not_verifiable);
				}
			}

			self.complete(ec, r);
		},
		handler, executor);
}

std::string provide_password()
{
	std::cout << "in provide_password " << std::endl
				<< "  ==> in thread " << this_thread_name()  << std::endl;

	std::string result;

	std::cout << "password: "; std::cout.flush();
	SetStdinEcho(false);
	std::cin >> result;
	SetStdinEcho(true);
	std::cout << std::endl;

	return result;
}

template <typename Handler, typename Executor>
auto async_ask_password(Handler &&handler, Executor &executor)
{
	return async_function_wrapper(std::move(handler), executor, &provide_password);
}

template <typename Handler, typename Executor>
auto async_ask_password_2(Handler &&handler, Executor &executor)
{
	return async_function_wrapper(std::move(handler), executor, &provide_password);
}


struct AsyncImpl
{
	void operator()(asio_system_ns::error_code ec, std::string password)
	{
		std::cout << "And the password is " << password << std::endl
				  << "  ==> in thread " << this_thread_name()  << std::endl;
	}
};

// --------------------------------------------------------------------

/*
	This example implementation sets up an SSH connection and then opens
	a terminal channel over this connection. The first thing it does when
	the channel is open is send a command to start an xterm.

	The code is not complete, there's no way to stop the connection yet.
	To do this, you should subclass terminal_channel and override closed()
	and stop the io_context from within.
*/

int main()
{
	using asio_ns::ip::tcp;

	const char* USER = getenv("USER");
	std::string user = USER ? USER : "test-account";

	// where are we?
	std::cout << "Starting in main thread " << this_thread_name() << std::endl;

	asio_ns::io_context io_context;
	auto strand = asio_ns::io_context::strand(io_context);

	pinch::connection_pool pool(io_context);

	// our executor
	my_queue queue;
	my_executor executor{&strand.context(), &queue};

	auto conn = pool.get(user, "localhost");
	// auto conn = pool.get(user, "localhost", 2022);
	// auto conn = pool.get(user, "localhost", 22, "test-account", "shell.example.com", 22);

	auto channel = std::make_shared<pinch::terminal_channel>(conn);

	auto msg = asio_ns::bind_executor(executor,
		[](const std::string &msg, const std::string &lang) {
			std::cout << "Message callback, msg = " << msg << ", lang = " << lang << std::endl;
		});

	channel->set_message_callbacks(msg, msg, msg);

	conn->set_callback_executor(executor);

	auto &known_hosts = pinch::known_hosts::instance();
	// known_hosts.load_host_file("/home/test-account/.ssh/known_hosts");
	conn->set_accept_host_key_handler(
		asio_ns::bind_executor(executor, 

		[](const std::string &host_name, const std::string &algorithm, const pinch::blob &key, pinch::host_key_state state) {
			std::cout << "validating " << host_name << " with algo " << algorithm << std::endl
					  << "  ==> in thread " << this_thread_name()  << std::endl;
			return pinch::host_key_reply::trust_once;
		}));

	conn->set_provide_password_callback(asio_ns::bind_executor(executor, &provide_password));

	auto open_cb = asio_ns::bind_executor(executor,
		[t = channel, conn, &queue, &io_context](const asio_system_ns::error_code &ec) {
			std::cout << "handler, ec = " << ec.message() << " thread: " << this_thread_name()  << std::endl;

			if (ec)
			{
				queue.stop();
				io_context.stop();
			}
			else
				read_from_channel(t);
		});

	channel->open_with_pty(80, 24, "vt220", true, true, "", std::move(open_cb));

	auto t = std::thread([&io_context]() {
		try
		{
			std::cout << "IO Context thread is " << this_thread_name() << std::endl;
			// asio_ns::executor_work_guard work(io_context.get_executor());
			io_context.run();
		}
		catch (const std::exception &ex)
		{
			std::cerr << ex.what() << std::endl;
		}
	});

	asio_ns::signal_set sigset(io_context, SIGHUP, SIGINT);
	sigset.async_wait([&io_context, &queue](asio_system_ns::error_code, int signal) { io_context.stop(); queue.stop(); });

	conn->keep_alive(std::chrono::seconds(5));

	queue.run();

	if (t.joinable())
		t.join();

	return 0;
}
