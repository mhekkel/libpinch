//        Copyright Maarten L. Hekkelman 2013-2021
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

//#define BOOST_ASIO_ENABLE_HANDLER_TRACKING

#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>

#include <deque>
#include <iostream>
#include <thread>

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

class thread_name
{
  public:
	static thread_name& instance()
	{
		static thread_name s_instance;
		return s_instance;
	}

	char operator()()
	{
		std::lock_guard lock(m_mutex);

		std::thread::id id = std::this_thread::get_id();

		auto i = m_names.find(id);
		if (i == m_names.end())
			return m_names[id] = 'A' + m_names.size();
		else
			return i->second;
	}

	std::mutex m_mutex;
	std::map<std::thread::id,char> m_names;
};

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

	void stop()
	{
		m_done = true;
	}

	void run()
	{
		while (not m_done)
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
	bool m_done = false;
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

template <typename Handler, typename Executor, typename... Args, typename Function>
auto async_function_wrapper(Handler &&handler, Executor &executor, Function func, Args... args)
{
	using result_type = decltype(func(args...));

	enum state
	{
		start,
		running,
		fetch
	};

	std::packaged_task<result_type()> task(std::bind(func, args...));
	std::future<result_type> result = task.get_future();

	return boost::asio::async_compose<Handler, void(boost::system::error_code, result_type)>(
		[
			task = std::move(task),
			result = std::move(result),
			state = start,
			&executor
		]
		(auto &self, boost::system::error_code ec = {}, result_type r = {}) mutable
		{
			std::cout << "composed in thread " << thread_name::instance()() << std::endl;

			if (not ec)
			{
				if (state == start)
				{
					state = running;
					boost::asio::execution::execute(
						boost::asio::require(executor, boost::asio::execution::blocking.never),
						std::move(self));


					// boost::asio::dispatch(executor, std::move(self));
					return;
				}

				state = fetch;
				task();

				try
				{
					r = result.get();
				}
				catch (...)
				{
					ec = pinch::error::make_error_code(pinch::error::by_application);
				}
			}

			self.complete(ec, r);
		},
		handler);
}

// --------------------------------------------------------------------

std::string provide_password()
{
	std::cout << "provide_password in thread " << thread_name::instance()() << std::endl;
	return "Deze is geheim!";
}

// --------------------------------------------------------------------

template<typename Handler, typename Executor>
auto async_provide_password(Executor &executor, Handler &&handler)
{
	return async_function_wrapper(std::move(handler), executor, &provide_password);
}

void run_coro(my_executor& executor, boost::asio::yield_context yield)
{
	std::cout << "run_coro in thread " << thread_name::instance()() << std::endl;

	boost::system::error_code ec;
	std::string pw = async_provide_password(executor, yield[ec]);

	std::cout << "(run_coro) The password is "<< pw << std::endl;
}

template<typename Handler, typename Provider>
auto async_provide_password_2(Provider &provider, Handler &&handler)
{
	auto executor = boost::asio::get_associated_executor(provider);
	return async_function_wrapper(std::move(handler), executor, provider);
}

template<typename Provider>
void run_coro_2(Provider &provider, boost::asio::yield_context yield)
{
	std::cout << "run_coro_2 in thread " << thread_name::instance()() << std::endl;

	boost::system::error_code ec;
	std::string pw = async_provide_password_2(provider, yield[ec]);

	std::cout << "(run_coro_2) The password is "<< pw << std::endl;
}

void run_coro_3(boost::asio::execution::any_executor<boost::asio::execution::blocking_t::never_t> executor, boost::asio::yield_context yield)
{
	std::cout << "run_coro_3 in thread " << thread_name::instance()() << std::endl;

	boost::system::error_code ec;
	std::string pw = async_provide_password(executor, yield[ec]);

	std::cout << "(run_coro_3) The password is "<< pw << std::endl;
}

// --------------------------------------------------------------------

void run_coro_4(boost::asio::execution::any_executor<boost::asio::execution::blocking_t::never_t> executor)
{
	auto handler = [](const boost::system::error_code &ec = {})
	{
		std::cout << "callback in thread " << thread_name::instance()() << std::endl;

	};
	using handler_type = decltype(handler);

	boost::asio::async_compose<handler_type, void(boost::system::error_code)>(
		[
			
		]
		(auto& self, const boost::system::error_code &ec = {}) mutable
		{
			std::cout << "operating in thread " << thread_name::instance()() << std::endl;

			self.complete(ec);
		}, handler, executor
	);
}

void run_coro_5(boost::asio::execution::any_executor<boost::asio::execution::blocking_t::never_t> executor)
{
	auto handler = [](const boost::system::error_code &ec = {})
	{
		std::cout << "callback in thread " << thread_name::instance()() << std::endl;

	};

	auto h2 = boost::asio::bind_executor(executor, handler);
	using handler_type = decltype(h2);

	boost::asio::async_compose<handler_type, void(boost::system::error_code)>(
		[
			
		]
		(auto& self, const boost::system::error_code &ec = {}) mutable
		{
			std::cout << "operating in thread " << thread_name::instance()() << std::endl;

			self.complete(ec);
		}, h2
	);
}

void run_coro_6(boost::asio::execution::any_executor<boost::asio::execution::blocking_t::never_t> executor,
	boost::asio::yield_context yield)
{
	std::cout << "run_coro_6 in thread " << thread_name::instance()() << std::endl;

	boost::system::error_code ec;
	std::string pw = async_provide_password(executor, yield[ec]);

	std::cout << "(run_coro_6) The password is "<< pw << std::endl;
}

void run_coro_7(boost::asio::execution::any_executor<boost::asio::execution::blocking_t::never_t> executor)
{
	std::cout << "run_coro_7 in thread " << thread_name::instance()() << std::endl;

	boost::system::error_code ec;
	auto pw = async_provide_password(executor, boost::asio::use_future);

	pw.wait();

	std::cout << "(run_coro_7) The password is "<< pw.get() << std::endl;
}


// --------------------------------------------------------------------

int main()
{
	// where are we?
	std::cout << "Starting in main thread " << thread_name::instance()() << std::endl;

	boost::asio::io_context io_context;
	boost::asio::strand<boost::asio::io_context::executor_type> strand(io_context.get_executor());

	// our executor
	my_queue queue;
	my_executor executor{&io_context, &queue};

	auto t = std::thread([&io_context]() {
		try
		{
			std::cout << "io_context::run thread: " << thread_name::instance()() << std::endl;
			boost::asio::executor_work_guard work(io_context.get_executor());
			io_context.run();
		}
		catch (const std::exception &ex)
		{
			std::cerr << ex.what() << std::endl;
		}
	});

	std::this_thread::sleep_for(std::chrono::milliseconds(250));

	std::thread qt([&queue]()
	{
		std::cout << "queue thread is " << thread_name::instance()() << std::endl;
		queue.run();
	});

	std::this_thread::sleep_for(std::chrono::milliseconds(250));

	std::cout << std::endl
			  << "First attempt, with direct my_executor" << std::endl
			  << std::endl;

	boost::asio::spawn(strand, std::bind(&run_coro, std::ref(executor), std::placeholders::_1));

	std::this_thread::sleep_for(std::chrono::milliseconds(250));

	std::cout << std::endl
			  << "Second attempt, using bind_executor" << std::endl
			  << std::endl;

	std::function<std::string()> provider = boost::asio::bind_executor(executor, &provide_password);

	boost::asio::spawn(strand, std::bind(&run_coro_2<decltype(provider)>, std::ref(provider), std::placeholders::_1));

	std::this_thread::sleep_for(std::chrono::milliseconds(250));

	std::cout << std::endl
			  << "Third attempt, with coroutines and a any_executor copy" << std::endl
			  << std::endl;

	using namespace boost::asio::execution;

	any_executor<blocking_t::never_t> ex_copy;
	ex_copy = executor;

	assert(ex_copy);

	boost::asio::spawn(executor, [&ex_copy](boost::asio::yield_context yield) mutable
	{
		run_coro_3(ex_copy, yield);
	});

	std::this_thread::sleep_for(std::chrono::milliseconds(250));

	std::cout << std::endl
			  << "Fourth attempt, a simple call to run_coro_4" << std::endl
			  << std::endl;

	run_coro_4(executor);

	std::this_thread::sleep_for(std::chrono::milliseconds(250));

	std::cout << std::endl
			  << "Fifth attempt, a simple call to run_coro_5" << std::endl
			  << std::endl;

	run_coro_5(executor);


	std::this_thread::sleep_for(std::chrono::milliseconds(250));

	std::cout << std::endl
			  << "coro 6" << std::endl
			  << std::endl;

	boost::asio::spawn(strand, std::bind(&run_coro_6, std::ref(executor), std::placeholders::_1));

	std::this_thread::sleep_for(std::chrono::milliseconds(250));

	std::cout << std::endl
			  << "coro 7" << std::endl
			  << std::endl;

	run_coro_7(executor);



	boost::asio::signal_set sigset(io_context, SIGHUP, SIGINT);
	sigset.async_wait([&io_context, &queue](boost::system::error_code, int signal)
	{
		io_context.stop();
		queue.stop();
	});


	if (t.joinable())
		t.join();
	
	if (qt.joinable())
		qt.join();

	return 0;
}
