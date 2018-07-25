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

Handling Requests
-----------------

Accessing Headers
^^^^^^^^^^^^^^^^^

Accessing Query Parameters
^^^^^^^^^^^^^^^^^^^^^^^^^^
