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
/// already trusted host keys.

namespace pinch
{

/// \brief The reply from the validate callback.
enum class host_key_reply
{
	reject,		///< Do not trust this host key and abort connecting
	trust_once,	///< Trust the host key, but do not store it for future use
	trusted		///< Trust the key and store it
};

/// \brief The class known_hosts is used to keep track of already trusted host keys.

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
	///
	/// The callback \a handler will be called using the executor, potentially running a separate thread.
	/// All I/O will be blocked in this thread until a reply is received.

	template <typename Handler, typename Executor>
	void register_handler(Handler &&handler, Executor &executor)
	{
		static_assert(std::is_assignable_v<validate_callback_type, decltype(handler)>, "Invalid handler");

		m_validate_cb = [&executor, this, handler = std::move(handler)](const std::string &host_name, const std::string &algorithm, const pinch::blob &key) {
			return async_validate(host_name, algorithm, key, handler, executor);
		};
	}

	/// \brief Return true if the host/algorithm/key pair should be trusted
	bool validate(const std::string &host, const std::string &algorithm, const blob &key);

  private:
	known_hosts() {}

	known_hosts(const known_hosts &) = delete;
	known_hosts &operator=(const known_hosts &) = delete;

	using validate_callback_type = std::function<host_key_reply(const std::string &host, const std::string &algorithm, const blob &key)>;

	/// \brief async validate support
	template <typename Handler, typename Executor>
	host_key_reply async_validate(const std::string &host_name, const std::string &algorithm, const pinch::blob &key, Handler &&handler, Executor &executor)
	{
		std::packaged_task<host_key_reply()> validate_task(
			[handler = std::move(handler), host_name, algorithm, key] { return handler(host_name, algorithm, key); });

		auto result = validate_task.get_future();

		boost::asio::dispatch(executor, [task = std::move(validate_task)]() mutable { task(); });

		result.wait();

		return result.get();
	}

	struct host_key
	{
		std::string m_host_name;
		std::string m_algorithm;
		blob m_key;

		bool compare(const std::string &host_name, const std::string &algorithm, const pinch::blob &key) const;
	};

	std::filesystem::path m_host_file;
	std::vector<host_key> m_host_keys;
	validate_callback_type m_validate_cb;

	static std::unique_ptr<known_hosts> s_instance;
};

} // namespace pinch