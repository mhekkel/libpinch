//            Copyright Maarten L. Hekkelman 2013
//  Distributed under the Boost Software License, Version 1.0.
//     (See accompanying file LICENSE_1_0.txt or copy at
//           http://www.boost.org/LICENSE_1_0.txt)

#pragma once

#ifndef LIBASSH_DOXYGEN_INVOKED

#include <boost/cstdint.hpp>
typedef boost::int8_t		int8;
typedef boost::uint8_t		uint8;
typedef boost::int16_t		int16;
typedef boost::uint16_t		uint16;
typedef boost::int32_t		int32;
typedef boost::uint32_t		uint32;
typedef boost::int64_t		int64;
typedef boost::uint64_t		uint64;

// see if we're using Visual C++, if so we have to include
// some VC specific include files to make the standard C++
// keywords work.

#if defined(_MSC_VER)

#include <SDKDDKVer.h>

#	if defined(_MSC_EXTENSIONS)		// why is it an extension to leave out something?
#		define and		&&
#		define and_eq	&=
#		define bitand	&
#		define bitor	|
#		define compl	~
#		define not		!
#		define not_eq	!=
#		define or		||
#		define or_eq	|=
#		define xor		^
#		define xor_eq	^=
#	endif // _MSC_EXTENSIONS

#	pragma warning (disable : 4355)	// this is used in Base Initializer list
#	pragma warning (disable : 4996)	// unsafe function or variable
#	pragma warning (disable : 4068)	// unknown pragma
#	pragma warning (disable : 4996)	// stl copy()
#	pragma warning (disable : 4800)	// BOOL conversion
#endif

// GCC 4.4 and before do not know nullptr
#if defined (__GNUC__) && !defined(__GXX_EXPERIMENTAL_CXX0X__)
const                        // this is a const object...
class {
public:
  template<class T>          // convertible to any type
    operator T*() const      // of null non-member
    { return 0; }            // pointer...
  template<class C, class T> // or any type of null
    operator T C::*() const  // member pointer...
    { return 0; }
private:
  void operator&() const;    // whose address can't be taken
} nullptr = {};              // and whose name is nullptr
#endif

/// fixes for cygwin/boost-1.43 combo
/// source:
///  https://svn.boost.org/trac/boost/attachment/ticket/4816/boost_asio_bug_cygwin_with_fix.cpp
#ifdef __CYGWIN__
//////////////// FIX STARTS HERE
/// 1st issue
#include <boost/asio/detail/pipe_select_interrupter.hpp>

/// 2nd issue
#include <termios.h>
#ifdef cfgetospeed
#define __cfgetospeed__impl(tp) cfgetospeed(tp)
#undef cfgetospeed
inline speed_t cfgetospeed(const struct termios *tp)
{
        //return ((tp)->c_ospeed);
        return __cfgetospeed__impl(tp);
}
#undef __cfgetospeed__impl
#endif /// cfgetospeed is a macro

/// 3rd issue
#undef __CYGWIN__
#include <boost/asio/detail/buffer_sequence_adapter.hpp>
#define __CYGWIN__
//////////////// FIX ENDS HERE
#endif
#endif
