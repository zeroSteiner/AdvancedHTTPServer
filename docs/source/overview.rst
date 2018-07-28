.. default-domain:: py
.. py:currentmodule:: advancedhttpserver

Getting Started
===============

The AdvancedHTTPServer module is composed of two main classes which implement
the bulk of the provided functionality. These two classes are
:py:class:`AdvancedHTTPServer` and :py:class:`RequestHandler`. Just like
Python's :py:mod:`http.server` module, the server takes a class **not an
instance of a class** and is responsible for responding to individual requests
at the TCP connection level. The :py:class:`RequestHandler` instance is
initialized automatically by the server when a request is received.

The following sections outline how to accomplish common tasks using
AdvancedHTTPServer.

Binding To Interfaces
---------------------

Bind to a single interface using the *address* (singular) keyword argument to
the :meth:`AdvancedHTTPServer.__init__` method.

.. code-block:: python

  server = AdvancedHTTPServer(RequestHandler, address=('0.0.0.0', 8081))

.. deprecated:: 2.0.12

  The *address* keyword argument has been deprecated in favor of the *addresses*
  keyword argument. It should not be used in new code.

Bind to one or more interfaces using the *addresses* (plural) keyword argument
to the :meth:`AdvancedHTTPServer.__init__` method.

.. code-block:: python

  server = AdvancedHTTPServer(RequestHandler, addresses=(
      # address,  port,  use ssl
      ('0.0.0.0', 80,    False),
      ('0.0.0.0', 8080,  False)
  ))

Enabling SSL
------------

To enable SSL, pass a PEM file path using the *ssl_certfile* keyword argument to
the :meth:`AdvancedHTTPServer.__init__` method. This will be the default
certificate. Additional certificates can be configured with TLS's Server Name
Indication (SNI) extension using the :meth:`AdvancedHTTPServer.add_sni_cert`
method.

.. code-block:: python

  server = AdvancedHTTPServer(RequestHandler,
      address=('0.0.0.0', 443),
      ssl_certfile='/path/to/the/certificate.pem'
  )

An insecure, self-signed certificate suitable for testing can be created using
the following openssl command:

.. code-block:: shell

  openssl req -new -x509 -days 365 -nodes -out cert.pem -keyout cert.pem

Enabling Basic Authentication
-----------------------------

Basic authentication can be enabled by adding credentials to a
:class:`AdvancedHTTPServer` instance using its
:meth:`AdvancedHTTPServer.auth_add_creds` method which takes a username and
password. The *pwtype* keyword argument can optionally be used to specify that
the password is a hash.

.. code-block:: python

  server = AdvancedHTTPServer(RequestHandler)
  server.auth_add_creds('admin', 'Sup3rS3cr3t!')

Using RPC
---------

AdvancedHTTPServer supports a custom form of RPC over HTTP using the ``RPC``
verb. To register RPC methods in a :py:class:`RequestHandler` they must be added
to the :py:attr:`RequestHandler.rpc_handler_map` dictionary. Unlike standard
HTTP request handlers, RPC request handlers can take arbitrary arguments and key
word arguments.

To define an RPC capable :py:class:`RequestHandler`:

.. code-block:: python

  # define a custom RequestHandler inheriting from the original
  class RPCHandler(RequestHandler):
      def on_init(self):
          # add to rpc_handler_map instead of handler_map
          self.rpc_handler_map['/xor'] = self.rpc_xor

      def rpc_xor(self, key, data):
          return ''.join(map(lambda x: chr(ord(x) ^ key), data))

  # initialize the server with the custom handler
  server = AdvancedHTTPServer(RPCHandler)

To call methods from an RPC capable :py:class:`RequestHandler`:

.. code-block:: python

  # in this case the server is running at http://localhost:8080/
  rpc = RPCClient(('localhost', 8080))
  rpc('xor', 1, 'test')

Passing Variables To The Request Handler
----------------------------------------

The :py:class:`RequestHandler` instance is passed the instance of the
:py:class:`ServerNonThreaded` which received the request. This attribute can be
used to pass forward values from the top level :py:class:`AdvancedHTTPServer`
object.

.. code-block:: python

  class DemoHandler(RequestHandler):
      def do_init(self):
          # access the value from the subserver instance
          self.some_value = self.server.some_value

  class DemoServer(AdvancedHTTPServer):
      def __init__(self, some_value, *args, **kwargs):
          # initialize the server first, this sets self.sub_servers
          super(DemoServer, self).__init__(*args, **kwargs)
          # iterate through self.sub_servers and set the attribute to forward
          for server in self.sub_servers:
              server.some_value = some_value

  some_value = 'Hello World!'
  server = DemoServer(some_value, DemoHandler)

Registering Request Handlers
----------------------------

AdvancedHTTPServer provides two distinct methods of registering methods to
handle either HTTP or RPC requests. These methods are provided so the user may
select the one they prefer to work with.

Modifying The Handler Map
^^^^^^^^^^^^^^^^^^^^^^^^^

The :py:class:`RequestHandler` class initializes the empty dictionaries for
:py:attr:`RequestHandler.handler_map` and
:py:attr:`RequestHandler.rpc_handler_map`. Both are keyed by a regular
expression which is applied to the path of the HTTP request to find a valid
handler method. These maps can be set by overriding the
:py:meth:`RequestHandler.on_init` method hook. The method must take a single
argument (in addition to the standard class method ``self`` argument which goes
first) which is the parsed query string.

.. code-block:: python

  class DemoHandler(RequestHandler):
      def on_init(self):
          # over ride on_init and add a generic http request handler method
          # this references a method which is defined later
          self.handler_map['^hello-world$'] = self.res_hello_world

      def res_hello_world(self, query):
          # ...
          return

Using RegisterPath
^^^^^^^^^^^^^^^^^^

The :py:class:`RegisterPath` class can be used as a decorator to allow handler
methods to be registered in the handler map. This approach does not require
writing a :py:class:`RequestHandler` class and the handlers can be simple
functions. The functions must take two arguments, the first is the active
:py:class:`RequestHandler` instance and the second is the parsed query string.

The *handler* keyword argument to :py:meth:`RegisterPath.__init__` specifies an
optional :py:class:`RequestHandler` to register the handler method with. By
default, the handler is treated as a global handler and is registered for all
:py:class:`RequestHandler` instances. Alternatively, a specific handler can be
specified either by a reference to the class or by the class's name.

.. code-block:: python

  # register a global handler for all RequestHandler instances
  @RegisterPath('^register-path-global$')
  def register_path_global(server, query):
      # ...
      return

  # register a handler only for DemoHandler by it's name
  @RegisterPath('^register-path-name$', 'DemoHandler')
  def register_path_name(server, query):
      # ...
      return
  # register a handler only for DemoHandler by it's class reference
  @RegisterPath('^register-path-class$', DemoHandler)
  def register_path_class(server, query):
      # ...
      return

Stacking RegisterPath
"""""""""""""""""""""

Since :py:class:`RegisterPath` does not modify or wrap the handler method it is
possible to "stack" the decorators to register a single handler for multiple
paths.

.. code-block:: python

  @RegisterPath('^register-path-class-double$', DemoHandler)
  @RegisterPath('^register-path-class$', DemoHandler)
  def register_path_class(server, query):
      # ...
      return

Handling Requests
-----------------

HTTP requests (and RPC requests) are dispatched to handlers defined by the
:py:class:`RequestHandler`. Two dictionaries exist, one for dispatching HTTP
requests and another specifically for RPC requests. Both dictionaries use
regular expressions as keys and functions to be called as value.

Standard HTTP requests such as GET and POST use the following standard function
signature:

.. code-block:: python

  def some_http_handler(self, query):
      message = b'Hello World!\r\n\r\n'
      self.send_response(200)
      self.send_header('Content-Type', 'text/plain')
      self.send_header('Content-Length', len(message))
      self.end_headers()
      self.wfile.write(message)
      return

RPC requests use an arbitrary function signature supporting both positional
(required) and keyword (optional) arguments. The caller must then specify these
arguments as necessary following the standard Python rules. The value returned
by an RPC handler is returned to the remote caller.

.. code-block:: python

  # define an RPC handler method accepting two arguments
  def some_rpc_handler(self, arg1, kwarg1=None):
      # return None to the caller
      return

Accessing Headers
^^^^^^^^^^^^^^^^^

Request headers can be accessed from both standard HTTP and RPC handlers through
the :py:attr:`RequestHandler.headers` attribute. Header strings are **case
insensitive**.

.. code-block:: python

  def some_http_handler(self, query):
      # get the Accept header if it exists, otherwise an empty string
      accept_header = self.headers.get('Accept', '')
      message = b'Accept Header: ' + accept_header.encode('utf-8')
      self.send_response(200)
      self.send_header('Content-Type', 'text/plain')
      self.send_header('Content-Length', len(message))
      self.end_headers()
      self.wfile.write(message)
      return

Accessing Query Parameters
^^^^^^^^^^^^^^^^^^^^^^^^^^

HTTP requests are passed the parsed query parameters in the *query* argument to
the registered handler. This parameter is a dictionary keyed by the field name
with a list of the values defined for the field name.

.. note::

  The parsed query data uses an array for the value to store each occurrence of
  field. Usually it's desirable to just access the first or last instance but it
  is important to note that all are available.

.. code-block:: python

  def some_http_handler(self, query):
      # get the value of id from the query or a list containing an empty string
      # so the first member can be referenced without raising an exception
      id_value = query.get('id', [''])[0]
      message = b'id value: ' + id_value.encode('utf-8')
      self.send_response(200)
      self.send_header('Content-Type', 'text/plain')
      self.send_header('Content-Length', len(message))
      self.end_headers()
      self.wfile.write(message)
      return
