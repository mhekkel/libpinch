//        Copyright Maarten L. Hekkelman 2013-2021
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include <pinch/pinch.hpp>

#include <boost/asio.hpp>

namespace pinch::detail
{

// --------------------------------------------------------------------

class operation
{
  public:
	virtual ~operation() {}

	virtual void complete(const boost::system::error_code &ec = {}, std::size_t bytes_transferred = 0) = 0;
};

// --------------------------------------------------------------------

template <typename Handler, typename IoExecutor,
          typename HandlerExecutor = typename boost::asio::associated_executor_t<Handler, IoExecutor>>
class handler_work
{
  public:
	handler_work(const handler_work &) = delete;
	handler_work &operator=(const handler_work &) = delete;

	explicit handler_work(Handler &handler) noexcept
		: m_io_executor()
		, m_executor(boost::asio::get_associated_executor(handler, m_io_executor))
		, m_ex_guard(m_executor)
		, m_ex_io_guard(m_io_executor)
	{
	}

	handler_work(Handler &handler, const IoExecutor &io_ex) noexcept
		: m_io_executor(io_ex)
		, m_executor(boost::asio::get_associated_executor(handler, m_io_executor))
		, m_ex_guard(m_executor)
		, m_ex_io_guard(m_io_executor)
	{
	}

	static void start(Handler &handler) noexcept
	{
	}

	static void start(Handler &handler, const IoExecutor &io_ex) noexcept
	{
	}

	~handler_work()
	{
	}

	template <typename Function>
	void complete(Function &function, Handler &handler)
	{
		boost::asio::dispatch(m_executor, std::forward<Function>(function));
	}

  private:
	IoExecutor m_io_executor;
	HandlerExecutor m_executor;
	boost::asio::executor_work_guard<HandlerExecutor> m_ex_guard;
	boost::asio::executor_work_guard<IoExecutor> m_ex_io_guard;
};

// --------------------------------------------------------------------

template <typename Handler, typename... Args>
struct binder
{
	template <typename T>
	binder(int, T &&handler, const Args &...args)
		: m_handler(std::forward<T>(handler))
		, m_args(args...)
	{
	}

	binder(Handler &handler, const Args &...args)
		: m_handler(std::forward<Handler>(handler))
		, m_args(args...)
	{
	}

	binder(const binder &other)
		: m_handler(other.m_handler)
		, m_args(other.m_args)
	{
	}

	binder(binder &&other)
		: m_handler(std::move(other.m_handler))
		, m_args(std::move(other.m_args))
	{
	}

	// void operator()()
	// {
	// 	std::invoke(m_handler, static_cast<const Args&>(m_args));
	// }

	void operator()()
	{
		std::apply(m_handler, m_args);
	}

	Handler m_handler;
	std::tuple<Args...> m_args;
};

} // namespace pinch::detail
