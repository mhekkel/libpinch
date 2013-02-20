//            Copyright Maarten L. Hekkelman 2013
//  Distributed under the Boost Software License, Version 1.0.
//     (See accompanying file LICENSE_1_0.txt or copy at
//           http://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include <boost/system/error_code.hpp>

namespace assh {

enum error_msg {
	SSH_MSG_DISCONNECT = 1,
	SSH_MSG_IGNORE,
	SSH_MSG_UNIMPLEMENTED,
	SSH_MSG_DEBUG,
	SSH_MSG_SERVICE_REQUEST,
	SSH_MSG_SERVICE_ACCEPT,

	SSH_MSG_KEXINIT = 20,
	SSH_MSG_NEWKEYS,

/*	Numbers 30-49 used for kex packets.
	Different kex methods may reuse message numbers in
	this range. */

	SSH_MSG_KEXDH_INIT = 30,
	SSH_MSG_KEXDH_REPLY,

 	SSH_MSG_USERAUTH_REQUEST = 50,
	SSH_MSG_USERAUTH_FAILURE,
	SSH_MSG_USERAUTH_SUCCESS,
	SSH_MSG_USERAUTH_BANNER,
	
	SSH_MSG_USERAUTH_INFO_REQUEST = 60,
	SSH_MSG_USERAUTH_INFO_RESPONSE,

	SSH_MSG_GLOBAL_REQUEST = 80,
	SSH_MSG_REQUEST_SUCCESS,
	SSH_MSG_REQUEST_FAILURE,

	SSH_MSG_CHANNEL_OPEN = 90,
	SSH_MSG_CHANNEL_OPEN_CONFIRMATION,
	SSH_MSG_CHANNEL_OPEN_FAILURE,
	SSH_MSG_CHANNEL_WINDOW_ADJUST,
	SSH_MSG_CHANNEL_DATA,
	SSH_MSG_CHANNEL_EXTENDED_DATA,
	SSH_MSG_CHANNEL_EOF,
	SSH_MSG_CHANNEL_CLOSE,
	SSH_MSG_CHANNEL_REQUEST,
	SSH_MSG_CHANNEL_SUCCESS,
	SSH_MSG_CHANNEL_FAILURE,
};

namespace error {

enum ssh_errors
{
	unimplemented = SSH_MSG_UNIMPLEMENTED,
	userauth_failure = SSH_MSG_USERAUTH_FAILURE,
	request_failure = SSH_MSG_REQUEST_FAILURE,
	channel_open_failure = SSH_MSG_CHANNEL_OPEN_FAILURE,
	channel_failure = SSH_MSG_CHANNEL_FAILURE,
	
	require_password
};

enum disconnect_errors
{
	host_not_allowed_to_connect = 1,
	protocol_error,
	key_exchange_failed,
	host_key_verification_failed,
	reserved,
	mac_error,
	compression_error,
	service_not_available,
	protocol_version_not_supported,
	host_key_not_verifiable,
	connection_lost,
	by_application,
	too_many_connections,
	auth_cancelled_by_user,
	no_more_auth_methods_available,
	illegal_user_name,
	not_authenticated
};

boost::system::error_category& ssh_category();
boost::system::error_category& disconnect_category();

}
}

namespace boost {
namespace system {

template<> struct is_error_code_enum<assh::error::ssh_errors>
{
  static const bool value = true;
};

template<> struct is_error_code_enum<assh::error::disconnect_errors>
{
  static const bool value = true;
};

} // namespace system
} // namespace boost

namespace assh {
namespace error {

inline boost::system::error_code make_error_code(ssh_errors e)
{
	return boost::system::error_code(static_cast<int>(e), ssh_category());
}

inline boost::system::error_code make_error_code(disconnect_errors e)
{
	return boost::system::error_code(static_cast<int>(e), disconnect_category());
}

} // namespace error
}
