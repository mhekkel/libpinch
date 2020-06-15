#define BOOST_ASIO_ENABLE_HANDLER_TRACKING

#include <boost/asio.hpp>
#include <iostream>
#include <deque>

#include "assh/connection.hpp"

using namespace assh;

template <typename Type>
class service_id : public boost::asio::execution_context::id
{
};

class connection_service : public boost::asio::execution_context::service
{
  public:

	using executor_type = boost::asio::executor;

	static service_id<connection_service> id;

	struct implementation_type
	{
		boost::asio::ip::tcp::socket* m_socket = nullptr;
		boost::asio::streambuf m_response;
		bool m_authenticated = false;
	};

	explicit connection_service(boost::asio::io_context& ctx)
		: boost::asio::execution_context::service(ctx)
		, m_context(ctx)
	{
	}

	boost::asio::io_context& get_io_context()
	{
		return m_context;
	}

	void construct(implementation_type& impl)
	{
		impl.m_socket = new boost::asio::ip::tcp::socket{ get_io_context() };
	}

	void destroy(implementation_type& impl)
	{
		impl.m_socket->close();
		delete impl.m_socket;
	}

	virtual void shutdown() noexcept override
	{

	}


	struct operation
	{
		virtual void complete(boost::system::error_code ec) = 0;
	};

	struct basic_connect_op : public operation
	{
		basic_connect_op(implementation_type& impl, const std::string& host, uint16_t port)
			: m_work(boost::asio::make_work_guard(impl.m_socket->get_executor()))
		{

		}

		boost::asio::executor_work_guard<boost::asio::ip::tcp::socket::executor_type> m_work;
	};

	template<typename Handler>
	struct connect_op : public basic_connect_op
	{
		connect_op(implementation_type& impl, const std::string& host, uint16_t port, Handler&& handler)
			: basic_connect_op(impl, host, port)
			, m_handler(std::move(handler))
		{
		}

		virtual void complete(boost::system::error_code ec)
		{
			m_handler(ec);
		}

		Handler m_handler;
	};

	template<typename CompletionToken, typename IOExecutor>
	void async_connect(implementation_type& impl, const std::string& host, uint16_t port,
		CompletionToken&& token, const IOExecutor& io_ex)
	{
		auto op = new connect_op(impl, host, port, std::forward<CompletionToken>(token));
		m_operations.push_back(op);
	}

	bool is_connected(const implementation_type& impl) const
	{
		return impl.m_authenticated;
	}

  private:
	boost::asio::io_context& m_context;
	std::deque<operation*> m_operations;
};

service_id<connection_service> connection_service::id;

class basic_connection : public boost::asio::basic_io_object<connection_service>
{
  public:
	
	using base_type = boost::asio::basic_io_object<connection_service>;
	using executor_type = boost::asio::executor;

	basic_connection(boost::asio::io_context& context)
		: base_type(context)
	{

	}

	template<typename CompletionToken>
	auto async_connect(const std::string& host, uint16_t port, CompletionToken&& token)
	{
		return boost::asio::async_initiate<CompletionToken, void(boost::system::error_code)>(
			initiate_async_connect(this), token, host, port
		);
	}

	bool is_connected() const
	{
		get_service().is_connected(get_implementation());
	}

	struct initiate_async_connect
	{
		using executor_type = basic_connection::executor_type;

		initiate_async_connect(basic_connection* self)
			: m_self(self) {}

		executor_type get_executor() const noexcept
		{
			return m_self->get_executor();
		}

		template<typename CompletionToken>
		void operator()(CompletionToken&& token, const std::string& host, uint16_t port)
		{
			m_self->get_service().async_connect(m_self->get_implementation(),
				host, port, std::forward<CompletionToken>(token), get_executor());
		}

		basic_connection* m_self;
	};
};



int main() {

	boost::asio::io_context io_context;

	::basic_connection c(io_context);

	c.async_connect("localhost", 16, [](boost::system::error_code ec)
	{
		std::cout << "handler, ec = " << ec << std::endl;
	});

	io_context.run();

	assert(c.is_connected());

	return 0;
}