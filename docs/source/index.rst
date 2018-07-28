AdvancedHTTPServer
==================

AdvancedHTTPServer is a light weight module that provides a set of classes for
quickly making HTTP servers for a variety of purposes. It focuses on a light and
powerful design with an emphasis on portability. It was designed after and
builds upon Python's standard :py:mod:`http.server` module module.
AdvancedHTTPServer is released under the BSD license and can be freely
distributed and packaged with other software.

Features
--------

AdvancedHTTPServer provides out of the box support for additional commonly
needed features such as:

- Threaded request handling
- Binding to multiple interfaces
- SSL and SNI support
- Registering handler functions to HTTP resources
- A default robots.txt file
- Basic authentication
- The HTTP verbs GET, HEAD, POST, and OPTIONS
- Remote Procedure Call (RPC) over HTTP
- WebSockets

.. _technical-docs:

.. toctree::
   :caption: Technical Documentation
   :numbered:
   :maxdepth: 1

   overview.rst
   advancedhttpserver.rst
