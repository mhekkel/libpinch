//        Copyright Maarten L. Hekkelman 2013-2021
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

/// \brief helper function and classes for async operations

#include "pinch/asio.hpp"

namespace pinch::detail
{

// --------------------------------------------------------------------
/// \brief Abstract base class for all asynchronous operations

class operation
{
  public:
	virtual ~operation() {}

	virtual void complete(const system_ns::error_code &ec = {}, std::size_t bytes_transferred = 0) = 0;
};

// --------------------------------------------------------------------
/// \brief looks and works like a copy of the same code in asio

template <typename Handler, typename IoExecutor,
	typename HandlerExecutor = typename asio_ns::associated_executor_t<Handler, IoExecutor>>
class handler_work
{
  public:
	handler_work(const handler_work &) = delete;
	handler_work &operator=(const handler_work &) = delete;

	explicit handler_work(Handler &handler) noexcept
		: m_io_executor()
		, m_executor(asio_ns::get_associated_executor(handler, m_io_executor))
		, m_ex_guard(m_executor)
		, m_ex_io_guard(m_io_executor)
	{
	}

	handler_work(Handler &handler, const IoExecutor &io_ex) noexcept
		: m_io_executor(io_ex)
		, m_executor(asio_ns::get_associated_executor(handler, m_io_executor))
		, m_ex_guard(m_executor)
		, m_ex_io_guard(m_io_executor)
	{
	}

	template <typename Function>
	void complete(Function &function, Handler &handler)
	{
		asio_ns::dispatch(m_executor, std::forward<Function>(function));
	}

  private:
	IoExecutor m_io_executor;
	HandlerExecutor m_executor;
	asio_ns::executor_work_guard<HandlerExecutor> m_ex_guard;
	asio_ns::executor_work_guard<IoExecutor> m_ex_io_guard;
};

// --------------------------------------------------------------------
/// \brief Alternative to boost's binder1 and binder2, takes any nr of arguments

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

	void operator()()
	{
		std::apply(m_handler, m_args);
	}

	Handler m_handler;
	std::tuple<Args...> m_args;
};

} // namespace pinch::detail