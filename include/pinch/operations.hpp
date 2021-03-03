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

	virtual void complete(const boost::system::error_code& ec = {}, std::size_t bytes_transferred = 0) = 0;
};

template <typename Handler, typename IoExecutor,
	typename HandlerExecutor = typename boost::asio::associated_executor_t<Handler, IoExecutor>>
class handler_work
{
  public:

	handler_work(const handler_work&) = delete;
	handler_work& operator=(const handler_work&) = delete;

	explicit handler_work(Handler& handler) noexcept
		: m_io_executor()
		, m_executor(boost::asio::get_associated_executor(handler, m_io_executor))
	{
	}

	handler_work(Handler& handler, const IoExecutor& io_ex) noexcept
		: m_io_executor(io_ex),
		m_executor(boost::asio::get_associated_executor(handler, m_io_executor))
	{
	}

	static void start(Handler& handler) noexcept
	{
		HandlerExecutor ex(boost::asio::get_associated_executor(handler));
		ex.on_work_started();
	}

	static void start(Handler& handler, const IoExecutor& io_ex) noexcept
	{
		HandlerExecutor ex(boost::asio::get_associated_executor(handler, io_ex));
		ex.on_work_started();
		io_ex.on_work_started();
	}

	~handler_work()
	{
		m_io_executor.on_work_finished();
		m_executor.on_work_finished();
	}

	template <typename Function>
	void complete(Function& function, Handler& handler)
	{
		m_executor.dispatch(std::forward<Function>(function),
			boost::asio::get_associated_allocator(handler));
	}

  private:
	IoExecutor m_io_executor;
	HandlerExecutor m_executor;
};

// --------------------------------------------------------------------

template <typename Handler, typename Arg1>
struct binder1
{
	template<typename T>
	binder1(int, T&& handler, const Arg1& arg1)
		: m_handler(std::forward<T>(handler))
		, m_arg_1(arg1)
	{
	}

	binder1(Handler& handler, const Arg1& arg1)
		: m_handler(BOOST_ASIO_MOVE_CAST(Handler)(handler))
		, m_arg_1(arg1)
	{
	}

	binder1(const binder1& other)
		: m_handler(other.m_handler)
		, m_arg_1(other.m_arg_1)
	{
	}

	binder1(binder1&& other)
		: m_handler(std::move(other.m_handler))
		, m_arg_1(std::move(other.m_arg_1))
	{
	}

	void operator()()
	{
		m_handler(static_cast<const Arg1&>(m_arg_1));
	}

	void operator()() const
	{
		m_handler(m_arg_1);
	}

	Handler m_handler;
	Arg1 m_arg_1;
};

// --------------------------------------------------------------------


template <typename Handler, typename Arg1, typename Arg2>
struct binder2
{
	template<typename T>
	binder2(int, T&& handler, const Arg1& arg1, const Arg2& arg2)
		: m_handler(std::forward<T>(handler))
		, m_arg_1(arg1)
		, m_arg_2(arg2)
	{
	}

	binder2(Handler& handler, const Arg1& arg1, const Arg2& arg2)
		: m_handler(BOOST_ASIO_MOVE_CAST(Handler)(handler))
		, m_arg_1(arg1)
		, m_arg_2(arg2)
	{
	}

	binder2(const binder2& other)
		: m_handler(other.m_handler)
		, m_arg_1(other.m_arg_1)
		, m_arg_2(other.m_arg_2)
	{
	}

	binder2(binder2&& other)
		: m_handler(std::move(other.m_handler))
		, m_arg_1(std::move(other.m_arg_1))
		, m_arg_2(std::move(other.m_arg_2))
	{
	}

	void operator()()
	{
		m_handler(static_cast<const Arg1&>(m_arg_1), static_cast<const Arg2&>(m_arg_2));
	}

	void operator()() const
	{
		m_handler(m_arg_1, m_arg_2);
	}

	Handler m_handler;
	Arg1 m_arg_1;
	Arg2 m_arg_2;
};

}
