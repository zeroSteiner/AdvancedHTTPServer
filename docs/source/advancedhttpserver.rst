:mod:`advancedhttpserver` -- API Reference
==========================================

.. module:: advancedhttpserver
   :synopsis: API Reference

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

.. autoclass:: ServerNonThreaded
   :members:

.. autoclass:: ServerTestCase
   :members:

.. autoclass:: ServerThreaded
   :members:


.. autoclass:: WebSocketHandler
   :members:

Exceptions
----------

.. autoexception:: RPCError
   :members:
   :undoc-members:

.. autoexception:: RPCConnectionError
   :members:
