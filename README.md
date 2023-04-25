libpinch
========

This library provides asynchronous SSH for use in client applications. The history of this code goes back to somewhere around the year 2000 when I added SFTP support to my text editor Pepper. After Pepper I thought it would be nice to have a terminal application supporting SSH and this is how Salt came into existence. And now I'm taking a pinch of this Salt and put it into a library aptly named libpinch.

Building
--------

Building libpinch requires a modern C++ compiler with support for C++20 coroutines and a recent [ASIO](https://think-async.com/Asio/), and then version 1.26. This is tricky, since there are many problems when using any other version, including the ones available in Boost.

Another requirement is a recent version of [Crypto++](https://cryptopp.com/).

Libpinch uses [cmake](https://cmake.org).


Documentation
-------------

To be written :-)

License
-------

libpinch comes with a [Boost license](https://www.boost.org/users/license.html).
