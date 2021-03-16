//           Copyright Maarten L. Hekkelman 2021
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include <pinch/pinch.hpp>
#include <pinch/types.hpp>

#include <boost/asio/dispatch.hpp>

#include <filesystem>
#include <functional>
#include <future>
#include <string>
#include <type_traits>

/// \file This file contains the class known_hosts which is used to keep track of
/// already validated host keys.

namespace pinch
{

/// \brief Callback type for validating host keys
///
/// the signature is bool validate_host_key(host, alg, key) and the callback
/// should return true

/// \brief The class known_hosts is used to keep track of
/// 	   already validated host keys.

class known_hosts
{
  public:

	/// \brief known_hosts is a singleton
	static known_hosts &instance()
	{
		static std::unique_ptr<known_hosts> s_instance(new known_hosts);
		return *s_instance;
	}

	/// \brief Set the host file
	void set_host_file(std::filesystem::path host_file);

	/// \brief register a function that will return whether a host key
	/// should be considered known.
	///
	/// The callback \a handler will be called in the boost::io_context thread.

	template <typename Handler>
	void register_handler(Handler &&handler)
	{
		static_assert(std::is_assignable_v<validate_callback_type, decltype(handler)>, "Invalid handler");
		m_validate_cb = handler;
	}

	/// \brief register a function that will return whether a host key is valid, but from possibly another thread

	template <typename Handler, typename Executor>
	void register_handler(Handler &&handler, Executor &executor)
	{
		static_assert(std::is_assignable_v<validate_callback_type, decltype(handler)>, "Invalid handler");

		m_validate_cb = [&executor, this, handler = std::move(handler)](const std::string &host_name, const std::string &algorithm, const pinch::blob &key) {
			return async_validate(host_name, algorithm, key, handler, executor);
		};
	}

	bool validate(const std::string &host, const std::string &algorithm, const blob &key);

  private:

	known_hosts() {}

	known_hosts(const known_hosts &) = delete;
	known_hosts &operator=(const known_hosts &) = delete;

	using validate_callback_type = std::function<bool(const std::string &host, const std::string &algorithm, const blob &key)>;

	/// \brief async validate support
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

	struct host_key
	{
		std::string name;
		std::string algorithm;
		blob key;
	};

	std::filesystem::path m_host_file;
	std::vector<host_key> m_host_keys;
	validate_callback_type m_validate_cb;

	static std::unique_ptr<known_hosts> s_instance;
};
} // namespace pinch