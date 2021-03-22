//        Copyright Maarten L. Hekkelman 2013-2021
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

//#define BOOST_ASIO_ENABLE_HANDLER_TRACKING

#include <boost/asio.hpp>

#include <deque>
#include <iostream>

#include <type_traits>

#include <boost/algorithm/string.hpp>
#include <boost/iostreams/copy.hpp>
#include <boost/iostreams/filtering_stream.hpp>

#include "pinch/channel.hpp"
#include "pinch/connection.hpp"
#include "pinch/connection_pool.hpp"
#include "pinch/crypto-engine.hpp"
#include "pinch/known_hosts.hpp"
#include "pinch/ssh_agent.hpp"
#include "pinch/terminal_channel.hpp"

namespace ba = boost::algorithm;
namespace io = boost::iostreams;

// --------------------------------------------------------------------

class my_queue
{
  public:
	struct handler_base
	{
		virtual ~handler_base() {}
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

	void run()
	{
		for (;;)
		{
			{
				std::unique_lock lock(m_mutex);
				m_cv.wait_for(lock, std::chrono::milliseconds(100));
			}

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
};

class my_executor
{
  public:
	boost::asio::execution_context *m_context;
	my_queue *m_queue;

	bool operator==(const my_executor &other) const noexcept
	{
		return m_context == other.m_context;
	}

	bool operator!=(const my_executor &other) const noexcept
	{
		return !(*this == other);
	}

	boost::asio::execution_context &query(boost::asio::execution::context_t) const noexcept
	{
		return *m_context;
	}

	static constexpr boost::asio::execution::blocking_t::never_t query(
		boost::asio::execution::blocking_t) noexcept
	{
		// This executor always has blocking.never semantics.
		return boost::asio::execution::blocking.never;
	}

	template <class F>
	void execute(F &&f) const
	{
		m_queue->submit(std::move(f));
	}
};

boost::asio::streambuf buffer;

void read_from_channel(pinch::channel_ptr ch, int start = 1)
{
	boost::asio::async_read(*ch, buffer, boost::asio::transfer_at_least(1),
		[ch, start](const boost::system::error_code &ec, std::size_t bytes_transferred) mutable {
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

// --------------------------------------------------------------------

// attempt to fetch a result asynchronously

template <typename Handler, typename Executor>
bool async_validate(const std::string &host_name, const std::string &algorithm, const pinch::blob &key, Handler &&handler, Executor &executor)
{
	std::packaged_task<bool()> validate_task(
		[handler = std::move(handler), host_name, algorithm, key] { return handler(host_name, algorithm, key); });

	auto result = validate_task.get_future();

	boost::asio::dispatch(executor, [task = std::move(validate_task)]() mutable {
		task();
	});

	result.wait();

	return result.get();
}

// another attempt to fetch a result asynchronously

bool validate_host_key(const std::string &host, const std::string &algo, const pinch::blob &blob)
{
	std::cout << " validate_host_key in thread: 0x" << std::hex << std::this_thread::get_id() << std::endl;
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

	return boost::asio::async_compose<Handler, void(boost::system::error_code, result_type)>(
		[task = std::move(task),
			result = std::move(result),
			state = start,
			executor](auto &self, boost::system::error_code ec = {}, result_type r = {}) mutable {
			if (not ec)
			{
				if (state == start)
				{
					state = running;
					task();
					boost::asio::dispatch(executor, std::move(self));
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
				<< "  ==> in thread 0x" << std::hex << std::this_thread::get_id() << std::endl;

	return "sssh... geheim!";
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
	void operator()(boost::system::error_code ec, std::string password)
	{
		std::cout << "And the password is " << password << std::endl
				  << "  ==> in thread 0x" << std::hex << std::this_thread::get_id() << std::endl;
	}
};

// --------------------------------------------------------------------

int main()
{
	using boost::asio::ip::tcp;

	// where are we?
	std::cout << "Starting in main thread 0x" << std::hex << std::this_thread::get_id() << std::endl;

	boost::asio::io_context io_context;

	pinch::connection_pool pool(io_context);

	// our executor
	my_queue queue;
	my_executor executor{&io_context, &queue};

	// auto conn = pool.get("maarten", "localhost", 2022);
	// auto conn = pool.get("maarten", "s4", 22);
	auto conn = pool.get("maarten", "localhost", 22, "maarten", "s4", 22);

	// auto channel = std::make_shared<pinch::terminal_channel>(proxied_conn);
	auto channel = std::make_shared<pinch::terminal_channel>(conn);

	auto msg = boost::asio::bind_executor(executor,
		[](const std::string &msg, const std::string &lang) {
			std::cout << "Mesage callback, msg = " << msg << ", lang = " << lang << std::endl;
		});

	channel->set_message_callbacks(msg, msg, msg);

	// auto validate = boost::asio::bind_executor(executor,
	// 	[](const std::string &host_name, const std::string &algorithm, const pinch::blob &key) {
	// 		std::cout << "validating " << host_name << " with algo " << algorithm << std::endl
	// 				  << "  ==> in thread 0x" << std::this_thread::get_id() << std::endl;
	// 		return true;
	// 	});

	// auto validate = std::bind(async_validate<decltype(v_cb), my_executor>, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, v_cb, executor);

	auto &known_hosts = pinch::known_hosts::instance();
	// known_hosts.load_host_file("/home/maarten/.ssh/known_hosts");
	conn->set_accept_host_key_handler(
		[](const std::string &host_name, const std::string &algorithm, const pinch::blob &key, pinch::host_key_state state) {
			std::cout << "validating " << host_name << " with algo " << algorithm << std::endl
					  << "  ==> in thread 0x" << std::hex << std::this_thread::get_id() << std::endl;
			return pinch::host_key_reply::trust_once;
		},
		executor);

	// conn->set_accept_host_key_handler(
	// 	[](const std::string &host_name, const std::string &algorithm, const pinch::blob &key, pinch::host_key_state state) {
	// 		std::cout << "validating " << host_name << " with algo " << algorithm << std::endl
	// 				  << "  ==> in thread 0x" << std::this_thread::get_id() << std::endl;
	// 		return pinch::host_key_reply::trust_once;
	// 	});

	auto open_cb = boost::asio::bind_executor(executor,
		[t = channel, conn](const boost::system::error_code &ec) {
			std::cout << "handler, ec = " << ec.message() << " thread: 0x" << std::hex << std::this_thread::get_id() << std::endl;

			read_from_channel(t);

			// conn->rekey();
		});

	channel->open_with_pty(80, 24, "vt220", true, true, "", std::move(open_cb));

	auto t = std::thread([&io_context]() {
		try
		{
			boost::asio::executor_work_guard work(io_context.get_executor());
			io_context.run();
		}
		catch (const std::exception &ex)
		{
			std::cerr << ex.what() << std::endl;
		}
	});

	auto vh = [](boost::system::error_code ec, bool b) {
		std::cout << "vh handler, ec = " << ec.message()
				  << " thread: 0x" << std::hex << std::this_thread::get_id() << std::endl
				  << "b is " << std::boolalpha << b << std::endl;
	};

	async_val(std::move(vh), executor, &validate_host_key, "s4", "sha-rsa", pinch::blob{});

	AsyncImpl impl;
	async_ask_password(std::move(impl), executor);

	conn->set_provide_password_callback(boost::asio::bind_executor(executor, &provide_password));
	conn->async_provide_password([](boost::system::error_code ec, std::string pw)
	{
		std::cout << "And the password is " << pw << std::endl
				  << "  ==> in thread 0x" << std::hex << std::this_thread::get_id() << std::endl;
	});

	boost::asio::signal_set sigset(io_context, SIGHUP, SIGINT);
	sigset.async_wait([&io_context](boost::system::error_code, int signal) { io_context.stop(); });

	queue.run();

	if (t.joinable())
		t.join();

	return 0;
}
