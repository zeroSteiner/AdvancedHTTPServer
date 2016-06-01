:mod:`advancedhttpserver` --- Python HTTP Server
================================================

.. module:: advancedhttpserver
   :synopsis: Python HTTP Server


Data
----

.. data:: g_serializer_drivers
   :annotation:

.. data:: g_ssl_has_server_sni
   :annotation:

Functions
---------

.. autofunction:: build_server_from_argparser

.. autofunction:: build_server_from_config

.. autofunction:: random_string

.. autofunction:: resolve_ssl_protocol_version

Classes
-------

.. autoclass:: AdvancedHTTPServer
   :members:
   :special-members: __init__
   :undoc-members:

.. autoclass:: RegisterPath
   :members:
   :special-members: __init__
   :undoc-members:

.. autoclass:: RequestHandler
   :members:

.. autoclass:: RPCClient
   :members:
   :special-members: __init__
   :undoc-members:

.. autoclass:: RPCClientCached
   :members:
   :undoc-members:

.. autoclass:: Serializer
   :members:
   :special-members: __init__
   :undoc-members:

.. autoclass:: ServerTestCase
   :members:

Exceptions
----------

.. autoexception:: RPCError
   :members:
   :undoc-members:
