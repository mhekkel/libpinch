//        Copyright Maarten L. Hekkelman 2013-2021
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

//#define BOOST_ASIO_ENABLE_HANDLER_TRACKING

#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>

#include <deque>
#include <iostream>

#include <type_traits>

#include <boost/algorithm/string.hpp>
#include <boost/iostreams/copy.hpp>
#include <boost/iostreams/filtering_stream.hpp>

#include <pinch/pinch.hpp>
#include <pinch/error.hpp>
#include "pinch/operations.hpp"
// #include "pinch/connection.hpp"
// #include "pinch/connection_pool.hpp"
// #include "pinch/crypto-engine.hpp"
// #include "pinch/known_hosts.hpp"
// #include "pinch/ssh_agent.hpp"
// #include "pinch/terminal_channel.hpp"

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

// --------------------------------------------------------------------

std::string provide_password()
{
	std::cout << "provide_password in thread 0x" << std::hex << std::this_thread::get_id() << std::endl;
	return "Deze is geheim!";
}

// --------------------------------------------------------------------

template<typename Handler, typename Executor>
auto async_provide_password(Executor &executor, Handler &&handler)
{
	return pinch::async_function_wrapper(std::move(handler), executor, &provide_password);
}

void run_coro(my_executor& executor, boost::asio::yield_context yield)
{
	std::cout << "coro in thread 0x" << std::hex << std::this_thread::get_id() << std::endl;

	boost::system::error_code ec;
	std::string pw = async_provide_password(executor, yield[ec]);

	std::cout << "The password is "<< pw << std::endl;
}

template<typename Handler, typename Provider>
auto async_provide_password_2(Provider &provider, Handler &&handler)
{
	auto executor = boost::asio::get_associated_executor(provider);
	return pinch::async_function_wrapper(std::move(handler), executor, provider);
}

template<typename Provider>
void run_coro_2(Provider &provider, boost::asio::yield_context yield)
{
	std::cout << "coro in thread 0x" << std::hex << std::this_thread::get_id() << std::endl;

	boost::system::error_code ec;
	std::string pw = async_provide_password_2(provider, yield[ec]);

	std::cout << "The password is "<< pw << std::endl;
}

void run_coro_3(boost::asio::execution::any_executor<boost::asio::execution::blocking_t::never_t> executor, boost::asio::yield_context yield)
{
	std::cout << "coro in thread 0x" << std::hex << std::this_thread::get_id() << std::endl;

	boost::system::error_code ec;
	std::string pw = async_provide_password(executor, yield[ec]);

	std::cout << "The password is "<< pw << std::endl;
}


// --------------------------------------------------------------------

int main()
{
	// where are we?
	std::cout << "Starting in main thread 0x" << std::hex << std::this_thread::get_id() << std::endl;

	boost::asio::io_context io_context;

	// our executor
	my_queue queue;
	my_executor executor{&io_context, &queue};


	auto t = std::thread([&io_context]() {
		try
		{
			std::cout << "io_context::run thread: 0x" << std::hex << std::this_thread::get_id() << std::endl;
			boost::asio::executor_work_guard work(io_context.get_executor());
			io_context.run();
		}
		catch (const std::exception &ex)
		{
			std::cerr << ex.what() << std::endl;
		}
	});

	// boost::asio::spawn(io_context.get_executor(), std::bind(&run_coro, std::ref(executor), std::placeholders::_1));

	// std::function<std::string()> provider = boost::asio::bind_executor(executor, &provide_password);

	// boost::asio::spawn(io_context.get_executor(), std::bind(&run_coro_2<decltype(provider)>, std::ref(provider), std::placeholders::_1));

	using namespace boost::asio::execution;

	any_executor<blocking_t::never_t> ex_copy(executor);

	assert(ex_copy);

	boost::asio::spawn(executor, [&ex_copy](boost::asio::yield_context yield) mutable
	{
		run_coro_3(ex_copy, yield);
	});
	// std::string pw = async_provide_password(ex_copy, []())

	boost::asio::signal_set sigset(io_context, SIGHUP, SIGINT);
	sigset.async_wait([&io_context](boost::system::error_code, int signal) { io_context.stop(); });

	queue.run();

	if (t.joinable())
		t.join();

	return 0;
}
