Introduction
============

The library libpinch offers an implementation of the SSH protocol as described in `RFC 4250 and following <https://tools.ietf.org/rfc/rfc4250.txt>`_. The code is based on `Asio <https://think-async.com/Asio/>`_ and uses `Crypto++ <https://cryptopp.com/>`_ for encryption and verification.

Synopsis
--------

Using libpinch is as easy as:

.. literalinclude:: ../examples/example-1.cpp
    :language: c++
    :start-after: //[ first_example
    :end-before: //]

The history
-----------

Somewhere in the year 2000 I added an SFTP option to my text editor Pepper. For this I decided to write my own SSH code. But then, since I had that code anyway I decided to write a terminal application called Salt. For pinch I took some of that code and rewrote so it can be offered as a stand alone library.

.. toctree::
   :maxdepth: 2
   :caption: Contents
   
   self
   api/library_root.rst
   genindex

