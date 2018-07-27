.. default-domain:: py
.. py:currentmodule:: advancedhttpserver

Getting Started
===============

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

Handling Requests
-----------------

HTTP requests (and RPC requests) are dispatched to handlers defined by the
:py:class:`RequestHandler`. Two dictionaries exist, one for dispatching HTTP
requests and another specifically for RPC requests. Both dictionaries use
regular expressions as keys and functions to be called as value.

Standard HTTP requests such as GET and POST use the following standard function
signature:

.. code-block::

  def some_http_handler(self, query):
      return

RPC requests use an arbitrary function signature supporting both positional
(required) and keyword (optional) arguments. The caller must then specify these
arguments as necessary following the standard Python rules. The value returned
by an RPC handler is returned to the remote caller.

.. code-block::

  # define an RPC handler method accepting two arguments
  def some_rpc_handler(self, arg1, kwarg1=None):
      # return None to the callers
      return

Accessing Headers
^^^^^^^^^^^^^^^^^

Accessing Query Parameters
^^^^^^^^^^^^^^^^^^^^^^^^^^
