#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  advancedhttpserver.py
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are
#  met:
#
#  * Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above
#    copyright notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
#  * Neither the name of the project nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#  pylint: disable=too-many-lines

#  Homepage: https://github.com/zeroSteiner/AdvancedHTTPServer
#  Author:   Spencer McIntyre (zeroSteiner)

# Config file example
FILE_CONFIG = """
[server]
ip = 0.0.0.0
port = 8080
web_root = /var/www/html
list_directories = True
# Set an ssl_cert to enable SSL
# ssl_cert = /path/to/cert.pem
# ssl_key = /path/to/cert.key
# ssl_version = TLSv1
"""

# The AdvancedHTTPServer systemd service unit file
# Quick how to:
#   1. Copy this file to /etc/systemd/system/pyhttpd.service
#   2. Edit the run parameters appropriately in the ExecStart option
#   3. Set configuration settings in /etc/pyhttpd.conf
#   4. Run "systemctl daemon-reload"
FILE_SYSTEMD_SERVICE_UNIT = """
[Unit]
Description=Python Advanced HTTP Server
After=network.target

[Service]
Type=simple
ExecStart=/sbin/runuser -l nobody -c "/usr/bin/python -m advhttpsrv -c /etc/pyhttpd.conf"
ExecStop=/bin/kill -INT $MAINPID

[Install]
WantedBy=multi-user.target
"""

__version__ = '2.0.10'
__all__ = (
	'AdvancedHTTPServer',
	'RegisterPath',
	'RequestHandler',
	'RPCClient',
	'RPCClientCached',
	'RPCError',
	'ServerTestCase',
	'WebSocketHandler',
	'build_server_from_argparser',
	'build_server_from_config'
)

import base64
import binascii
import datetime
import hashlib
import io
import json
import logging
import logging.handlers
import mimetypes
import os
import posixpath
import random
import re
import select
import shutil
import socket
import sqlite3
import ssl
import string
import struct
import sys
import threading
import time
import traceback
import unittest
import urllib
import zlib

if sys.version_info[0] < 3:
	import BaseHTTPServer
	import cgi as html
	import Cookie
	import httplib
	import SocketServer as socketserver
	import urlparse
	http = type('http', (), {'client': httplib, 'cookies': Cookie, 'server': BaseHTTPServer})
	urllib.parse = urlparse
	urllib.parse.quote = urllib.quote
	urllib.parse.unquote = urllib.unquote
	urllib.parse.urlencode = urllib.urlencode
	from ConfigParser import ConfigParser
else:
	import html
	import http.client
	import http.cookies
	import http.server
	import socketserver
	import urllib.parse
	from configparser import ConfigParser

g_handler_map = {}
g_serializer_drivers = {}
"""Dictionary of available drivers for serialization."""
g_ssl_has_server_sni = (getattr(ssl, 'HAS_SNI', False) and sys.version_info >= ((2, 7, 9) if sys.version_info[0] < 3 else (3, 4)))
"""An indication of if the environment offers server side SNI support."""

def _serialize_ext_dump(obj):
	if obj.__class__ == datetime.date:
		return 'datetime.date', obj.isoformat()
	elif obj.__class__ == datetime.datetime:
		return 'datetime.datetime', obj.isoformat()
	elif obj.__class__ == datetime.time:
		return 'datetime.time', obj.isoformat()
	raise TypeError('Unknown type: ' + repr(obj))

def _serialize_ext_load(obj_type, obj_value, default):
	if obj_type == 'datetime.date':
		return datetime.datetime.strptime(obj_value, '%Y-%m-%d').date()
	elif obj_type == 'datetime.datetime':
		return datetime.datetime.strptime(obj_value, '%Y-%m-%dT%H:%M:%S' + ('.%f' if '.' in obj_value else ''))
	elif obj_type == 'datetime.time':
		return datetime.datetime.strptime(obj_value, '%H:%M:%S' + ('.%f' if '.' in obj_value else '')).time()
	return default

def _json_default(obj):
	obj_type, obj_value = _serialize_ext_dump(obj)
	return {'__complex_type__': obj_type, 'value': obj_value}

def _json_object_hook(obj):
	return _serialize_ext_load(obj.get('__complex_type__'), obj.get('value'), obj)

g_serializer_drivers['application/json'] = {
	'dumps': lambda d: json.dumps(d, default=_json_default),
	'loads': lambda d, e: json.loads(d, object_hook=_json_object_hook)
}

try:
	import msgpack
except ImportError:
	has_msgpack = False
else:
	has_msgpack = True
	_MSGPACK_EXT_TYPES = {10: 'datetime.datetime', 11: 'datetime.date', 12: 'datetime.time'}
	def _msgpack_default(obj):
		obj_type, obj_value = _serialize_ext_dump(obj)
		obj_type = next(i[0] for i in _MSGPACK_EXT_TYPES.items() if i[1] == obj_type)
		if sys.version_info[0] == 3:
			obj_value = obj_value.encode('utf-8')
		return msgpack.ExtType(obj_type, obj_value)

	def _msgpack_ext_hook(code, obj_value):
		default = msgpack.ExtType(code, obj_value)
		if sys.version_info[0] == 3:
			obj_value = obj_value.decode('utf-8')
		obj_type = _MSGPACK_EXT_TYPES.get(code)
		return _serialize_ext_load(obj_type, obj_value, default)
	g_serializer_drivers['binary/message-pack'] = {
		'dumps': lambda d: msgpack.dumps(d, default=_msgpack_default),
		'loads': lambda d, e: msgpack.loads(d, encoding=e, ext_hook=_msgpack_ext_hook)
	}

if hasattr(logging, 'NullHandler'):
	logging.getLogger('AdvancedHTTPServer').addHandler(logging.NullHandler())

def random_string(size):
	"""
	Generate a random string of *size* length consisting of both letters
	and numbers. This function is not meant for cryptographic purposes
	and should not be used to generate security tokens.

	:param int size: The length of the string to return.
	:return: A string consisting of random characters.
	:rtype: str
	"""
	return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(size))

def resolve_ssl_protocol_version(version=None):
	"""
	Look up an SSL protocol version by name. If *version* is not specified, then
	the strongest protocol available will be returned.

	:param str version: The name of the version to look up.
	:return: A protocol constant from the :py:mod:`ssl` module.
	:rtype: int
	"""
	if version is None:
		protocol_preference = ('TLSv1_2', 'TLSv1_1', 'TLSv1', 'SSLv3', 'SSLv23', 'SSLv2')
		for protocol in protocol_preference:
			if hasattr(ssl, 'PROTOCOL_' + protocol):
				return getattr(ssl, 'PROTOCOL_' + protocol)
		raise RuntimeError('could not find a suitable ssl PROTOCOL_ version constant')
	elif isinstance(version, str):
		if not hasattr(ssl, 'PROTOCOL_' + version):
			raise ValueError('invalid ssl protocol version: ' + version)
		return getattr(ssl, 'PROTOCOL_' + version)
	raise TypeError("ssl_version() argument 1 must be str, not {0}".format(type(version).__name__))

def build_server_from_argparser(description=None, server_klass=None, handler_klass=None):
	"""
	Build a server from command line arguments. If a ServerClass or
	HandlerClass is specified, then the object must inherit from the
	corresponding AdvancedHTTPServer base class.

	:param str description: Description string to be passed to the argument parser.
	:param server_klass: Alternative server class to use.
	:type server_klass: :py:class:`.AdvancedHTTPServer`
	:param handler_klass: Alternative handler class to use.
	:type handler_klass: :py:class:`.RequestHandler`
	:return: A configured server instance.
	:rtype: :py:class:`.AdvancedHTTPServer`
	"""
	import argparse

	def _argp_dir_type(arg):
		if not os.path.isdir(arg):
			raise argparse.ArgumentTypeError("{0} is not a valid directory".format(repr(arg)))
		return arg

	def _argp_port_type(arg):
		if not arg.isdigit():
			raise argparse.ArgumentTypeError("{0} is not a valid port".format(repr(arg)))
		arg = int(arg)
		if arg < 0 or arg > 65535:
			raise argparse.ArgumentTypeError("{0} is not a valid port".format(repr(arg)))
		return arg

	description = (description or 'HTTP Server')
	server_klass = (server_klass or AdvancedHTTPServer)
	handler_klass = (handler_klass or RequestHandler)

	parser = argparse.ArgumentParser(conflict_handler='resolve', description=description, fromfile_prefix_chars='@')
	parser.epilog = 'When a config file is specified with --config only the --log, --log-file and --password options will be used.'
	parser.add_argument('-c', '--conf', dest='config', type=argparse.FileType('r'), help='read settings from a config file')
	parser.add_argument('-i', '--ip', dest='ip', default='0.0.0.0', help='the ip address to serve on')
	parser.add_argument('-L', '--log', dest='loglvl', choices=('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'), default='INFO', help='set the logging level')
	parser.add_argument('-p', '--port', dest='port', default=8080, type=_argp_port_type, help='port to serve on')
	parser.add_argument('-v', '--version', action='version', version=parser.prog + ' Version: ' + __version__)
	parser.add_argument('-w', '--web-root', dest='web_root', default='.', type=_argp_dir_type, help='path to the web root directory')
	parser.add_argument('--log-file', dest='log_file', help='log information to a file')
	parser.add_argument('--no-threads', dest='use_threads', action='store_false', default=True, help='disable threading')
	parser.add_argument('--password', dest='password', help='password to use for basic authentication')
	ssl_group = parser.add_argument_group('ssl options')
	ssl_group.add_argument('--ssl-cert', dest='ssl_cert', help='the ssl cert to use')
	ssl_group.add_argument('--ssl-key', dest='ssl_key', help='the ssl key to use')
	ssl_group.add_argument('--ssl-version', dest='ssl_version', choices=[p[9:] for p in dir(ssl) if p.startswith('PROTOCOL_')], help='the version of ssl to use')
	arguments = parser.parse_args()

	logging.getLogger('').setLevel(logging.DEBUG)
	console_log_handler = logging.StreamHandler()
	console_log_handler.setLevel(getattr(logging, arguments.loglvl))
	console_log_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-8s %(message)s"))
	logging.getLogger('').addHandler(console_log_handler)

	if arguments.log_file:
		main_file_handler = logging.handlers.RotatingFileHandler(arguments.log_file, maxBytes=262144, backupCount=5)
		main_file_handler.setLevel(logging.DEBUG)
		main_file_handler.setFormatter(logging.Formatter("%(asctime)s %(name)-30s %(levelname)-10s %(message)s"))
		logging.getLogger('').setLevel(logging.DEBUG)
		logging.getLogger('').addHandler(main_file_handler)

	if arguments.config:
		config = ConfigParser()
		config.readfp(arguments.config)
		server = build_server_from_config(
			config,
			'server',
			server_klass=server_klass,
			handler_klass=handler_klass
		)
	else:
		server = server_klass(
			handler_klass,
			address=(arguments.ip, arguments.port),
			use_threads=arguments.use_threads,
			ssl_certfile=arguments.ssl_cert,
			ssl_keyfile=arguments.ssl_key,
			ssl_version=arguments.ssl_version
		)
		server.serve_files_root = arguments.web_root

	if arguments.password:
		server.auth_add_creds('', arguments.password)
	return server

def build_server_from_config(config, section_name, server_klass=None, handler_klass=None):
	"""
	Build a server from a provided :py:class:`configparser.ConfigParser`
	instance. If a ServerClass or HandlerClass is specified, then the
	object must inherit from the corresponding AdvancedHTTPServer base
	class.

	:param config: Configuration to retrieve settings from.
	:type config: :py:class:`configparser.ConfigParser`
	:param str section_name: The section name of the configuration to use.
	:param server_klass: Alternative server class to use.
	:type server_klass: :py:class:`.AdvancedHTTPServer`
	:param handler_klass: Alternative handler class to use.
	:type handler_klass: :py:class:`.RequestHandler`
	:return: A configured server instance.
	:rtype: :py:class:`.AdvancedHTTPServer`
	"""
	server_klass = (server_klass or AdvancedHTTPServer)
	handler_klass = (handler_klass or RequestHandler)
	port = config.getint(section_name, 'port')
	web_root = None
	if config.has_option(section_name, 'web_root'):
		web_root = config.get(section_name, 'web_root')

	if config.has_option(section_name, 'ip'):
		ip = config.get(section_name, 'ip')
	else:
		ip = '0.0.0.0'
	ssl_certfile = None
	if config.has_option(section_name, 'ssl_cert'):
		ssl_certfile = config.get(section_name, 'ssl_cert')
	ssl_keyfile = None
	if config.has_option(section_name, 'ssl_key'):
		ssl_keyfile = config.get(section_name, 'ssl_key')
	ssl_version = None
	if config.has_option(section_name, 'ssl_version'):
		ssl_version = config.get(section_name, 'ssl_version')
	server = server_klass(
		handler_klass,
		address=(ip, port),
		ssl_certfile=ssl_certfile,
		ssl_keyfile=ssl_keyfile,
		ssl_version=ssl_version
	)

	if config.has_option(section_name, 'password_type'):
		password_type = config.get(section_name, 'password_type')
	else:
		password_type = 'md5'
	if config.has_option(section_name, 'password'):
		password = config.get(section_name, 'password')
		if config.has_option(section_name, 'username'):
			username = config.get(section_name, 'username')
		else:
			username = ''
		server.auth_add_creds(username, password, pwtype=password_type)
	cred_idx = 0
	while config.has_option(section_name, 'password' + str(cred_idx)):
		password = config.get(section_name, 'password' + str(cred_idx))
		if not config.has_option(section_name, 'username' + str(cred_idx)):
			break
		username = config.get(section_name, 'username' + str(cred_idx))
		server.auth_add_creds(username, password, pwtype=password_type)
		cred_idx += 1

	if web_root is None:
		server.serve_files = False
	else:
		server.serve_files = True
		server.serve_files_root = web_root
		if config.has_option(section_name, 'list_directories'):
			server.serve_files_list_directories = config.getboolean(section_name, 'list_directories')
	return server

class RegisterPath(object):
	"""
	Register a path and handler with the global handler map. This can be
	used as a decorator. If no handler is specified then the path and
	function will be registered with all :py:class:`.RequestHandler`
	instances.

	.. code-block:: python

	  @RegisterPath('^test$')
	  def handle_test(handler, query):
	      pass
	"""
	def __init__(self, path, handler=None, is_rpc=False):
		"""
		:param str path: The path regex to register the function to.
		:param str handler: A specific :py:class:`.RequestHandler` class to register the handler with.
		:param bool is_rpc: Whether the handler is an RPC handler or not.
		"""
		self.path = path
		self.is_rpc = is_rpc
		if handler is None or isinstance(handler, str):
			self.handler = handler
		elif hasattr(handler, '__name__'):
			self.handler = handler.__name__
		elif hasattr(handler, '__class__'):
			self.handler = handler.__class__.__name__
		else:
			raise ValueError('unknown handler: ' + repr(handler))

	def __call__(self, function):
		handler_map = g_handler_map.get(self.handler, {})
		handler_map[self.path] = (function, self.is_rpc)
		g_handler_map[self.handler] = handler_map
		return function

class RPCError(Exception):
	"""
	This class represents an RPC error either local or remote. Any errors
	in routines executed on the server will raise this error.
	"""
	def __init__(self, message, status, remote_exception=None):
		super(RPCError, self).__init__()
		self.message = message
		self.status = status
		self.remote_exception = remote_exception

	def __repr__(self):
		return "{0}(message='{1}', status={2}, remote_exception={3})".format(self.__class__.__name__, self.message, self.status, self.is_remote_exception)

	def __str__(self):
		if self.is_remote_exception:
			return 'a remote exception occurred'
		return "the server responded with {0} '{1}'".format(self.status, self.message)

	@property
	def is_remote_exception(self):
		"""
		This is true if the represented error resulted from an exception on the
		remote server.

		:type: bool
		"""
		return bool(self.remote_exception is not None)

class RPCClient(object):
	"""
	This object facilitates communication with remote RPC methods as
	provided by a :py:class:`.RequestHandler` instance.
	Once created this object can be called directly, doing so is the same
	as using the call method.

	This object uses locks internally to be thread safe. Only one thread
	can execute a function at a time.
	"""
	def __init__(self, address, use_ssl=False, username=None, password=None, uri_base='/', ssl_context=None):
		"""
		:param tuple address: The address of the server to connect to as (host, port).
		:param bool use_ssl: Whether to connect with SSL or not.
		:param str username: The username to authenticate with.
		:param str password: The password to authenticate with.
		:param str uri_base: An optional prefix for all methods.
		:param ssl_context: An optional SSL context to use for SSL related options.
		"""
		self.host = str(address[0])
		self.port = int(address[1])
		if not hasattr(self, 'logger'):
			self.logger = logging.getLogger('AdvancedHTTPServer.RPCClient')

		self.headers = None
		"""An optional dictionary of headers to include with each RPC request."""
		self.use_ssl = bool(use_ssl)
		self.ssl_context = ssl_context
		self.uri_base = str(uri_base)
		self.username = (None if username is None else str(username))
		self.password = (None if password is None else str(password))
		self.lock = threading.Lock()
		"""A :py:class:`threading.Lock` instance used to synchronize operations."""
		self.serializer = None
		"""The :py:class:`.Serializer` instance to use for encoding RPC data to the server."""
		self.set_serializer('application/json')
		self.reconnect()

	def __del__(self):
		self.client.close()

	def __reduce__(self):
		address = (self.host, self.port)
		return (self.__class__, (address, self.use_ssl, self.username, self.password, self.uri_base))

	def set_serializer(self, serializer_name, compression=None):
		"""
		Configure the serializer to use for communication with the server.
		The serializer specified must be valid and in the
		:py:data:`.g_serializer_drivers` map.

		:param str serializer_name: The name of the serializer to use.
		:param str compression: The name of a compression library to use.
		"""
		self.serializer = Serializer(serializer_name, charset='UTF-8', compression=compression)
		self.logger.debug('using serializer: ' + serializer_name)

	def __call__(self, *args, **kwargs):
		return self.call(*args, **kwargs)

	def encode(self, data):
		"""Encode data with the configured serializer."""
		return self.serializer.dumps(data)

	def decode(self, data):
		"""Decode data with the configured serializer."""
		return self.serializer.loads(data)

	def reconnect(self):
		"""Reconnect to the remote server."""
		self.lock.acquire()
		if self.use_ssl:
			self.client = http.client.HTTPSConnection(self.host, self.port, context=self.ssl_context)
		else:
			self.client = http.client.HTTPConnection(self.host, self.port)
		self.lock.release()

	def call(self, method, *args, **kwargs):
		"""
		Issue a call to the remote end point to execute the specified
		procedure.

		:param str method: The name of the remote procedure to execute.
		:return: The return value from the remote function.
		"""
		if kwargs:
			options = self.encode(dict(args=args, kwargs=kwargs))
		else:
			options = self.encode(args)

		headers = {}
		if self.headers:
			headers.update(self.headers)
		headers['Content-Type'] = self.serializer.content_type
		headers['Content-Length'] = str(len(options))
		headers['Connection'] = 'close'

		if self.username is not None and self.password is not None:
			headers['Authorization'] = 'Basic ' + base64.b64encode((self.username + ':' + self.password).encode('UTF-8')).decode('UTF-8')

		method = os.path.join(self.uri_base, method)
		self.logger.debug('calling RPC method: ' + method[1:])
		try:
			with self.lock:
				self.client.request('RPC', method, options, headers)
				resp = self.client.getresponse()
		except http.client.ImproperConnectionState:
			raise RPCError('improper connection state', None)
		if resp.status != 200:
			raise RPCError(resp.reason, resp.status)

		resp_data = resp.read()
		resp_data = self.decode(resp_data)
		if not ('exception_occurred' in resp_data and 'result' in resp_data):
			raise RPCError('missing response information', resp.status)
		if resp_data['exception_occurred']:
			raise RPCError('remote method incurred an exception', resp.status, remote_exception=resp_data['exception'])
		return resp_data['result']

class RPCClientCached(RPCClient):
	"""
	This object builds upon :py:class:`.RPCClient` and
	provides additional methods for cacheing results in memory.
	"""
	def __init__(self, *args, **kwargs):
		cache_db = kwargs.pop('cache_db', ':memory:')
		super(RPCClientCached, self).__init__(*args, **kwargs)
		self.cache_db = sqlite3.connect(cache_db, check_same_thread=False)
		cursor = self.cache_db.cursor()
		cursor.execute('CREATE TABLE IF NOT EXISTS cache (method TEXT NOT NULL, options_hash BLOB NOT NULL, return_value BLOB NOT NULL)')
		self.cache_db.commit()
		self.cache_lock = threading.Lock()

	def cache_call(self, method, *options):
		"""
		Call a remote method and store the result locally. Subsequent
		calls to the same method with the same arguments will return the
		cached result without invoking the remote procedure. Cached results are
		kept indefinitely and must be manually refreshed with a call to
		:py:meth:`.cache_call_refresh`.

		:param str method: The name of the remote procedure to execute.
		:return: The return value from the remote function.
		"""
		options_hash = self.encode(options)
		if len(options_hash) > 20:
			options_hash = hashlib.new('sha1', options_hash).digest()
		options_hash = sqlite3.Binary(options_hash)

		with self.cache_lock:
			cursor = self.cache_db.cursor()
			cursor.execute('SELECT return_value FROM cache WHERE method = ? AND options_hash = ?', (method, options_hash))
			return_value = cursor.fetchone()
		if return_value:
			return_value = bytes(return_value[0])
			return self.decode(return_value)
		return_value = self.call(method, *options)
		store_return_value = sqlite3.Binary(self.encode(return_value))
		with self.cache_lock:
			cursor = self.cache_db.cursor()
			cursor.execute('INSERT INTO cache (method, options_hash, return_value) VALUES (?, ?, ?)', (method, options_hash, store_return_value))
			self.cache_db.commit()
		return return_value

	def cache_call_refresh(self, method, *options):
		"""
		Call a remote method and update the local cache with the result
		if it already existed.

		:param str method: The name of the remote procedure to execute.
		:return: The return value from the remote function.
		"""
		options_hash = self.encode(options)
		if len(options_hash) > 20:
			options_hash = hashlib.new('sha1', options).digest()
		options_hash = sqlite3.Binary(options_hash)

		with self.cache_lock:
			cursor = self.cache_db.cursor()
			cursor.execute('DELETE FROM cache WHERE method = ? AND options_hash = ?', (method, options_hash))
		return_value = self.call(method, *options)
		store_return_value = sqlite3.Binary(self.encode(return_value))
		with self.cache_lock:
			cursor = self.cache_db.cursor()
			cursor.execute('INSERT INTO cache (method, options_hash, return_value) VALUES (?, ?, ?)', (method, options_hash, store_return_value))
			self.cache_db.commit()
		return return_value

	def cache_clear(self):
		"""Purge the local store of all cached function information."""
		with self.cache_lock:
			cursor = self.cache_db.cursor()
			cursor.execute('DELETE FROM cache')
			self.cache_db.commit()
		self.logger.info('the RPC cache has been purged')
		return

class ServerNonThreaded(http.server.HTTPServer, object):
	"""
	This class is used internally by :py:class:`.AdvancedHTTPServer` and
	is not intended for use by other classes or functions. It is responsible for
	listening on a single address, TCP port and SSL combination.
	"""
	def __init__(self, *args, **kwargs):
		self.__config = kwargs.pop('config')
		if not hasattr(self, 'logger'):
			self.logger = logging.getLogger('AdvancedHTTPServer')
		self.allow_reuse_address = True
		self.using_ssl = False
		super(ServerNonThreaded, self).__init__(*args, **kwargs)

	def get_config(self):
		return self.__config

	def finish_request(self, request, client_address):
		try:
			super(ServerNonThreaded, self).finish_request(request, client_address)
		except IOError:
			self.logger.warning('IOError encountered in finish_request')
		except KeyboardInterrupt:
			self.logger.warning('KeyboardInterrupt encountered in finish_request')
			self.shutdown()

	def server_bind(self, *args, **kwargs):
		self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		super(ServerNonThreaded, self).server_bind(*args, **kwargs)

	def shutdown(self, *args, **kwargs):
		try:
			self.socket.shutdown(socket.SHUT_RDWR)
		except socket.error:
			pass
		self.socket.close()

class ServerThreaded(socketserver.ThreadingMixIn, ServerNonThreaded):
	"""
	This class is used internally by :py:class:`.AdvancedHTTPServer` and
	is not intended for use by other classes or functions. It is responsible for
	listening on a single address, TCP port and SSL combination.
	"""
	daemon_threads = True

class RequestHandler(http.server.BaseHTTPRequestHandler, object):
	"""
	This is the primary http request handler class of the
	AdvancedHTTPServer framework. Custom request handlers must inherit
	from this object to be compatible. Instances of this class are created
	automatically. This class will handle standard HTTP GET, HEAD, OPTIONS,
	and POST requests. Callback functions called handlers can be registered
	to resource paths using regular expressions in the *handler_map*
	attribute for GET HEAD and POST requests and *rpc_handler_map* for RPC
	requests. Non-RPC handler functions that are not class methods of
	the request handler instance will be passed the instance of the
	request handler as the first argument.
	"""
	if not mimetypes.inited:
		mimetypes.init()  # try to read system mime.types
	extensions_map = mimetypes.types_map.copy()
	extensions_map.update({
		'': 'application/octet-stream',  # Default
		'.py': 'text/plain',
		'.rb': 'text/plain',
		'.c':  'text/plain',
		'.h':  'text/plain',
	})
	protocol_version = 'HTTP/1.1'
	wbufsize = 4096
	web_socket_handler = None
	"""An optional class to handle Web Sockets. This class must be derived from :py:class:`.WebSocketHandler`."""
	def __init__(self, *args, **kwargs):
		self.cookies = None
		self.path = None
		self.wfile = None
		self._wfile = None
		self.server = args[2]
		self.headers_active = False
		"""Whether or not the request is in the sending headers phase."""
		self.handler_map = {}
		"""The dict object which maps regular expressions of resources to the functions which should handle them."""
		self.rpc_handler_map = {}
		"""The dict object which maps regular expressions of RPC functions to their handlers."""
		for map_name in (None, self.__class__.__name__):
			handler_map = g_handler_map.get(map_name, {})
			for path, function_info in handler_map.items():
				function, function_is_rpc = function_info
				if function_is_rpc:
					self.rpc_handler_map[path] = function
				else:
					self.handler_map[path] = function

		self.basic_auth_user = None
		"""The name of the user if the current request is using basic authentication."""
		self.query_data = None
		"""The parameter data that has been passed to the server parsed as a dict."""
		self.raw_query_data = None
		"""The raw data that was parsed into the :py:attr:`.query_data` attribute."""
		self.__config = self.server.get_config()
		"""A reference to the configuration provided by the server."""
		self.on_init()
		super(RequestHandler, self).__init__(*args, **kwargs)

	def setup(self, *args, **kwargs):
		ret = super(RequestHandler, self).setup(*args, **kwargs)
		self._wfile = self.wfile
		return ret

	def on_init(self):
		"""
		This method is meant to be over ridden by custom classes. It is
		called as part of the __init__ method and provides an opportunity
		for the handler maps to be populated with entries or the config to be
		customized.
		"""
		pass  # over ride me

	def __get_handler(self, is_rpc=False):
		handler = None
		handler_map = (self.rpc_handler_map if is_rpc else self.handler_map)
		for (path_regex, handler) in handler_map.items():
			if re.match(path_regex, self.path):
				break
		else:
			return (None, None)
		is_method = False
		self_handler = None
		if hasattr(handler, '__name__'):
			self_handler = getattr(self, handler.__name__, None)
		if self_handler is not None and (handler == self_handler.__func__ or handler == self_handler):
			is_method = True
		return (handler, is_method)

	def version_string(self):
		return self.__config['server_version']

	def respond_file(self, file_path, attachment=False, query=None):
		"""
		Respond to the client by serving a file, either directly or as
		an attachment.

		:param str file_path: The path to the file to serve, this does not need to be in the web root.
		:param bool attachment: Whether to serve the file as a download by setting the Content-Disposition header.
		"""
		del query
		file_path = os.path.abspath(file_path)
		try:
			file_obj = open(file_path, 'rb')
		except IOError:
			self.respond_not_found()
			return None
		self.send_response(200)
		self.send_header('Content-Type', self.guess_mime_type(file_path))
		fs = os.fstat(file_obj.fileno())
		self.send_header('Content-Length', str(fs[6]))
		if attachment:
			file_name = os.path.basename(file_path)
			self.send_header('Content-Disposition', 'attachment; filename=' + file_name)
		self.send_header('Last-Modified', self.date_time_string(fs.st_mtime))
		self.end_headers()
		shutil.copyfileobj(file_obj, self.wfile)
		file_obj.close()
		return

	def respond_list_directory(self, dir_path, query=None):
		"""
		Respond to the client with an HTML page listing the contents of
		the specified directory.

		:param str dir_path: The path of the directory to list the contents of.
		"""
		del query
		try:
			dir_contents = os.listdir(dir_path)
		except os.error:
			self.respond_not_found()
			return None
		if os.path.normpath(dir_path) != self.__config['serve_files_root']:
			dir_contents.append('..')
		dir_contents.sort(key=lambda a: a.lower())
		displaypath = html.escape(urllib.parse.unquote(self.path), quote=True)

		f = io.BytesIO()
		encoding = sys.getfilesystemencoding()
		f.write(b'<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">\n')
		f.write(b'<html>\n<title>Directory listing for ' + displaypath.encode(encoding) + b'</title>\n')
		f.write(b'<body>\n<h2>Directory listing for ' + displaypath.encode(encoding) + b'</h2>\n')
		f.write(b'<hr>\n<ul>\n')
		for name in dir_contents:
			fullname = os.path.join(dir_path, name)
			displayname = linkname = name
			# Append / for directories or @ for symbolic links
			if os.path.isdir(fullname):
				displayname = name + "/"
				linkname = name + "/"
			if os.path.islink(fullname):
				displayname = name + "@"
				# Note: a link to a directory displays with @ and links with /
			f.write(('<li><a href="' + urllib.parse.quote(linkname) + '">' + html.escape(displayname, quote=True) + '</a>\n').encode(encoding))
		f.write(b'</ul>\n<hr>\n</body>\n</html>\n')
		length = f.tell()
		f.seek(0)

		self.send_response(200)
		self.send_header('Content-Type', 'text/html; charset=' + encoding)
		self.send_header('Content-Length', length)
		self.end_headers()
		shutil.copyfileobj(f, self.wfile)
		f.close()
		return

	def respond_not_found(self):
		"""Respond to the client with a default 404 message."""
		self.send_response_full(b'Resource Not Found\n', status=404)
		return

	def respond_redirect(self, location='/'):
		"""
		Respond to the client with a 301 message and redirect them with
		a Location header.

		:param str location: The new location to redirect the client to.
		"""
		self.send_response(301)
		self.send_header('Content-Length', 0)
		self.send_header('Location', location)
		self.end_headers()
		return

	def respond_server_error(self, status=None, status_line=None, message=None):
		"""
		Handle an internal server error, logging a traceback if executed
		within an exception handler.

		:param int status: The status code to respond to the client with.
		:param str status_line: The status message to respond to the client with.
		:param str message: The body of the response that is sent to the client.
		"""
		(ex_type, ex_value, ex_traceback) = sys.exc_info()
		if ex_type:
			(ex_file_name, ex_line, _, _) = traceback.extract_tb(ex_traceback)[-1]
			line_info = "{0}:{1}".format(ex_file_name, ex_line)
			log_msg = "encountered {0} in {1}".format(repr(ex_value), line_info)
			self.server.logger.error(log_msg, exc_info=True)
		status = (status or 500)
		status_line = (status_line or http.client.responses.get(status, 'Internal Server Error')).strip()
		self.send_response(status, status_line)
		message = (message or status_line)
		if isinstance(message, (str, bytes)):
			self.send_header('Content-Length', len(message))
			self.end_headers()
			if isinstance(message, str):
				self.wfile.write(message.encode(sys.getdefaultencoding()))
			else:
				self.wfile.write(message)
		elif hasattr(message, 'fileno'):
			fs = os.fstat(message.fileno())
			self.send_header('Content-Length', fs[6])
			self.end_headers()
			shutil.copyfileobj(message, self.wfile)
		else:
			self.end_headers()
		return

	def respond_unauthorized(self, request_authentication=False):
		"""
		Respond to the client that the request is unauthorized.

		:param bool request_authentication: Whether to request basic authentication information by sending a WWW-Authenticate header.
		"""
		headers = {}
		if request_authentication:
			headers['WWW-Authenticate'] = 'Basic realm="' + self.__config['server_version'] + '"'
		self.send_response_full(b'Unauthorized', status=401, headers=headers)
		return

	def dispatch_handler(self, query=None):
		"""
		Dispatch functions based on the established handler_map. It is
		generally not necessary to override this function and doing so
		will prevent any handlers from being executed. This function is
		executed automatically when requests of either GET, HEAD, or POST
		are received.

		:param dict query: Parsed query parameters from the corresponding request.
		"""
		query = (query or {})
		# normalize the path
		# abandon query parameters
		self.path = self.path.split('?', 1)[0]
		self.path = self.path.split('#', 1)[0]
		original_path = urllib.parse.unquote(self.path)
		self.path = posixpath.normpath(original_path)
		words = self.path.split('/')
		words = filter(None, words)
		tmp_path = ''
		for word in words:
			_, word = os.path.splitdrive(word)
			_, word = os.path.split(word)
			if word in (os.curdir, os.pardir):
				continue
			tmp_path = os.path.join(tmp_path, word)
		self.path = tmp_path

		if self.path == 'robots.txt' and self.__config['serve_robots_txt']:
			self.send_response_full(self.__config['robots_txt'])
			return

		self.cookies = http.cookies.SimpleCookie(self.headers.get('cookie', ''))
		handler, is_method = self.__get_handler(is_rpc=False)
		if handler is not None:
			try:
				handler(*((query,) if is_method else (self, query)))
			except Exception:
				self.respond_server_error()
			return

		if not self.__config['serve_files']:
			self.respond_not_found()
			return

		file_path = self.__config['serve_files_root']
		file_path = os.path.join(file_path, tmp_path)
		if os.path.isfile(file_path) and os.access(file_path, os.R_OK):
			self.respond_file(file_path, query=query)
			return
		elif os.path.isdir(file_path) and os.access(file_path, os.R_OK):
			if not original_path.endswith('/'):
				# redirect browser, doing what apache does
				destination = self.path + '/'
				if self.command == 'GET' and self.query_data:
					destination += '?' + urllib.parse.urlencode(self.query_data, True)
				self.respond_redirect(destination)
				return
			for index in ['index.html', 'index.htm']:
				index = os.path.join(file_path, index)
				if os.path.isfile(index) and os.access(index, os.R_OK):
					self.respond_file(index, query=query)
					return
			if self.__config['serve_files_list_directories']:
				self.respond_list_directory(file_path, query=query)
				return
		self.respond_not_found()
		return

	def send_response(self, *args, **kwargs):
		if self.wfile != self._wfile:
			self.wfile.close()
			self.wfile = self._wfile
		super(RequestHandler, self).send_response(*args, **kwargs)
		self.headers_active = True

		# in the event that the http request is invalid, all attributes may not be defined
		headers = getattr(self, 'headers', {})
		protocol_version = getattr(self, 'protocol_version', 'HTTP/1.0').upper()
		if headers.get('Connection', None) == 'keep-alive' and protocol_version == 'HTTP/1.1':
			connection = 'keep-alive'
		else:
			connection = 'close'
		self.send_header('Connection', connection)

	def send_response_full(self, message, content_type='text/plain; charset=UTF-8', status=200, headers=None):
		self.send_response(status)
		self.send_header('Content-Type', content_type)
		self.send_header('Content-Length', len(message))
		if headers is not None:
			for header, value in headers.items():
				self.send_header(header, value)
		self.end_headers()
		self.wfile.write(message)
		return

	def end_headers(self):
		super(RequestHandler, self).end_headers()
		self.headers_active = False
		if self.command == 'HEAD':
			self.wfile.flush()
			self.wfile = open(os.devnull, 'wb')

	def guess_mime_type(self, path):
		"""
		Guess an appropriate MIME type based on the extension of the
		provided path.

		:param str path: The of the file to analyze.
		:return: The guessed MIME type of the default if non are found.
		:rtype: str
		"""
		_, ext = posixpath.splitext(path)
		if ext in self.extensions_map:
			return self.extensions_map[ext]
		ext = ext.lower()
		if ext in self.extensions_map:
			return self.extensions_map[ext]
		else:
			return self.extensions_map['']

	def stock_handler_respond_unauthorized(self, query):
		"""This method provides a handler suitable to be used in the handler_map."""
		del query
		self.respond_unauthorized()
		return

	def stock_handler_respond_not_found(self, query):
		"""This method provides a handler suitable to be used in the handler_map."""
		del query
		self.respond_not_found()
		return

	def check_authorization(self):
		"""
		Check for the presence of a basic auth Authorization header and
		if the credentials contained within in are valid.

		:return: Whether or not the credentials are valid.
		:rtype: bool
		"""
		try:
			store = self.__config.get('basic_auth')
			if store is None:
				return True
			auth_info = self.headers.get('Authorization')
			if not auth_info:
				return False
			auth_info = auth_info.split()
			if len(auth_info) != 2 or auth_info[0] != 'Basic':
				return False
			auth_info = base64.b64decode(auth_info[1]).decode(sys.getdefaultencoding())
			username = auth_info.split(':')[0]
			password = ':'.join(auth_info.split(':')[1:])
			password_bytes = password.encode(sys.getdefaultencoding())
			if hasattr(self, 'custom_authentication'):
				if self.custom_authentication(username, password):
					self.basic_auth_user = username
					return True
				return False
			if not username in store:
				self.server.logger.warning('received invalid username: ' + username)
				return False
			password_data = store[username]

			if password_data['type'] == 'plain':
				if password == password_data['value']:
					self.basic_auth_user = username
					return True
			elif hashlib.new(password_data['type'], password_bytes).digest() == password_data['value']:
				self.basic_auth_user = username
				return True
			self.server.logger.warning('received invalid password from user: ' + username)
		except Exception:
			pass
		return False

	def cookie_get(self, name):
		"""
		Check for a cookie value by name.

		:param str name: Name of the cookie value to retreive.
		:return: Returns the cookie value if it's set or None if it's not found.
		"""
		if not hasattr(self, 'cookies'):
			return None
		if self.cookies.get(name):
			return self.cookies.get(name).value
		return None

	def cookie_set(self, name, value):
		"""
		Set the value of a client cookie. This can only be called while
		headers can be sent.

		:param str name: The name of the cookie value to set.
		:param str value: The value of the cookie to set.
		"""
		if not self.headers_active:
			raise RuntimeError('headers have already been ended')
		cookie = "{0}={1}; Path=/; HttpOnly".format(name, value)
		self.send_header('Set-Cookie', cookie)

	def do_GET(self):
		if not self.check_authorization():
			self.respond_unauthorized(request_authentication=True)
			return
		uri = urllib.parse.urlparse(self.path)
		self.path = uri.path
		self.query_data = urllib.parse.parse_qs(uri.query)
		if self.web_socket_handler is not None and self.headers.get('upgrade', '').lower() == 'websocket':
			self.web_socket_handler(self)  # pylint: disable=not-callable
			return

		self.dispatch_handler(self.query_data)
		return
	do_HEAD = do_GET

	def do_POST(self):
		if not self.check_authorization():
			self.respond_unauthorized(request_authentication=True)
			return
		content_length = int(self.headers.get('content-length', 0))
		data = self.rfile.read(content_length)
		self.raw_query_data = data
		content_type = self.headers.get('content-type', '')
		content_type = content_type.split(';', 1)[0]
		self.query_data = {}
		try:
			if not isinstance(data, str):
				data = data.decode(self.get_content_type_charset())
			if content_type.startswith('application/json'):
				data = json.loads(data)
				if isinstance(data, dict):
					self.query_data = dict([(i[0], [i[1]]) for i in data.items()])
			else:
				self.query_data = urllib.parse.parse_qs(data, keep_blank_values=1)
		except Exception:
			self.respond_server_error(400)
		else:
			self.dispatch_handler(self.query_data)
		return

	def do_OPTIONS(self):
		available_methods = list(x[3:] for x in dir(self) if x.startswith('do_'))
		if 'RPC' in available_methods and len(self.rpc_handler_map) == 0:
			available_methods.remove('RPC')
		self.send_response(200)
		self.send_header('Content-Length', 0)
		self.send_header('Allow', ', '.join(available_methods))
		self.end_headers()

	def do_RPC(self):
		if not self.check_authorization():
			self.respond_unauthorized(request_authentication=True)
			return

		data_length = self.headers.get('content-length')
		if data_length is None:
			self.send_error(411)
			return

		content_type = self.headers.get('content-type')
		if content_type is None:
			self.send_error(400, 'Missing Header: Content-Type')
			return

		try:
			data_length = int(self.headers.get('content-length'))
			data = self.rfile.read(data_length)
		except Exception:
			self.send_error(400, 'Invalid Data')
			return

		try:
			serializer = Serializer.from_content_type(content_type)
		except ValueError:
			self.send_error(400, 'Invalid Content-Type')
			return

		try:
			data = serializer.loads(data)
		except Exception:
			self.server.logger.warning('serializer failed to load data')
			self.send_error(400, 'Invalid Data')
			return

		if isinstance(data, (list, tuple)):
			meth_args = data
			meth_kwargs = {}
		elif isinstance(data, dict):
			meth_args = data.get('args', ())
			meth_kwargs = data.get('kwargs', {})
		else:
			self.server.logger.warning('received data does not match the calling convention')
			self.send_error(400, 'Invalid Data')
			return

		rpc_handler, is_method = self.__get_handler(is_rpc=True)
		if not rpc_handler:
			self.respond_server_error(501)
			return

		if not is_method:
			meth_args = (self,) + tuple(meth_args)
		response = {'result': None, 'exception_occurred': False}
		try:
			response['result'] = rpc_handler(*meth_args, **meth_kwargs)
		except Exception as error:
			response['exception_occurred'] = True
			exc_name = "{0}.{1}".format(error.__class__.__module__, error.__class__.__name__)
			response['exception'] = dict(name=exc_name, message=getattr(error, 'message', None))
			self.server.logger.error('error: ' + exc_name + ' occurred while calling rpc method: ' + self.path, exc_info=True)

		try:
			response = serializer.dumps(response)
		except Exception:
			self.respond_server_error(message='Failed To Pack Response')
			return

		self.send_response(200)
		self.send_header('Content-Type', serializer.content_type)
		self.end_headers()

		self.wfile.write(response)
		return

	def log_error(self, msg_format, *args):
		self.server.logger.warning(self.address_string() + ' ' + msg_format % args)

	def log_message(self, msg_format, *args):
		self.server.logger.info(self.address_string() + ' ' + msg_format % args)

	def get_query(self, name, default=None):
		"""
		Get a value from the query data that was sent to the server.

		:param str name: The name of the query value to retrieve.
		:param default: The value to return if *name* is not specified.
		:return: The value if it exists, otherwise *default* will be returned.
		:rtype: str
		"""
		return self.query_data.get(name, [default])[0]

	def get_content_type_charset(self, default='UTF-8'):
		"""
		Inspect the Content-Type header to retrieve the charset that the client
		has specified.

		:param str default: The default charset to return if none exists.
		:return: The charset of the request.
		:rtype: str
		"""
		encoding = default
		header = self.headers.get('Content-Type', '')
		idx = header.find('charset=')
		if idx > 0:
			encoding = (header[idx + 8:].split(' ', 1)[0] or encoding)
		return encoding

class WakeupFd(object):
	__slots__ = ('read_fd', 'write_fd')
	def __init__(self):
		self.read_fd, self.write_fd = os.pipe()

	def close(self):
		os.close(self.read_fd)
		os.close(self.write_fd)

	def fileno(self):
		return self.read_fd

class WebSocketHandler(object):
	"""
	A handler for web socket connections.
	"""
	_opcode_continue = 0x00
	_opcode_text = 0x01
	_opcode_binary = 0x02
	_opcode_close = 0x08
	_opcode_ping = 0x09
	_opcode_pong = 0x0a
	_opcode_names = {
		_opcode_continue: 'continue',
		_opcode_text: 'text',
		_opcode_binary: 'binary',
		_opcode_close: 'close',
		_opcode_ping: 'ping',
		_opcode_pong: 'pong'
	}
	guid = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
	def __init__(self, handler):
		"""
		:param handler: The :py:class:`RequestHandler` instance that is handling the request.
		"""
		self.handler = handler
		if not hasattr(self, 'logger'):
			self.logger = logging.getLogger('AdvancedHTTPServer.WebSocketHandler')
		headers = self.handler.headers
		client_extensions = headers.get('Sec-WebSocket-Extensions', '')
		self.client_extensions = [extension.strip() for extension in client_extensions.split(',')]
		key = headers.get('Sec-WebSocket-Key', None)
		digest = hashlib.sha1((key + self.guid).encode('utf-8')).digest()
		handler.send_response(101, 'Switching Protocols')
		handler.send_header('Upgrade', 'WebSocket')
		handler.send_header('Connection', 'Upgrade')
		handler.send_header('Sec-WebSocket-Accept', base64.b64encode(digest).decode('utf-8'))
		handler.end_headers()
		handler.wfile.flush()
		self.lock = threading.Lock()

		self.connected = True
		self.logger.info('web socket has been connected')
		self.on_connected()

		self._last_buffer = b''
		self._last_opcode = 0
		self._last_sent_opcode = 0

		while self.connected:
			try:
				self._process_message()
			except socket.error:
				self.logger.warning('there was a socket error while processing web socket messages')
				self.close()
			except Exception:
				self.logger.error('there was an error while processing web socket messages', exc_info=True)
				self.close()
		self.handler.close_connection = 1

	def _decode_string(self, data):
		str = data.decode('utf-8')
		if sys.version_info[0] == 3:
			return str
		# raise an exception on surrogates in python 2.7 to more closely replicate 3.x behaviour
		for idx, ch in enumerate(str):
			if 0xD800 <= ord(ch) <= 0xDFFF:
				raise UnicodeDecodeError('utf-8', '', idx, idx + 1, 'invalid continuation byte')
		return str

	def _process_message(self):
		byte_0 = self.handler.rfile.read(1)
		if not byte_0:
			self.close()
			return
		byte_0 = ord(byte_0)
		if byte_0 & 0x70:
			self.close()
			return
		fin = bool(byte_0 & 0x80)
		opcode = byte_0 & 0x0f
		length = ord(self.handler.rfile.read(1)) & 0x7f
		if length == 126:
			length = struct.unpack('>H', self.handler.rfile.read(2))[0]
		elif length == 127:
			length = struct.unpack('>Q', self.handler.rfile.read(8))[0]
		masks = [b for b in self.handler.rfile.read(4)]
		if sys.version_info[0] < 3:
			masks = map(ord, masks)

		payload = bytearray(self.handler.rfile.read(length))
		for idx, char in enumerate(payload):
			payload[idx] = char ^ masks[idx % 4]
		payload = bytes(payload)
		self.logger.debug("received message (len: {0:,} opcode: 0x{1:02x} fin: {2})".format(len(payload), opcode, fin))
		if fin:
			if opcode == self._opcode_continue:
				opcode = self._last_opcode
				payload = self._last_buffer + payload
				self._last_buffer = b''
				self._last_opcode = 0
			elif self._last_buffer and opcode in (self._opcode_binary, self._opcode_text):
				self.logger.warning('closing connection due to unflushed buffer in new data frame')
				self.close()
				return
			self.on_message(opcode, payload)
			return

		if opcode > 0x02:
			self.logger.warning('closing connection due to fin flag not set on opcode > 0x02')
			self.close()
			return
		if opcode:
			if self._last_buffer:
				self.logger.warning('closing connection due to unflushed buffer in new continuation frame')
				self.close()
				return
			self._last_buffer = payload
			self._last_opcode = opcode
		else:
			self._last_buffer += payload

	def close(self):
		"""
		Close the web socket connection and stop processing results. If the
		connection is still open, a WebSocket close message will be sent to the
		peer.
		"""
		if not self.connected:
			return
		self.connected = False
		if self.handler.wfile.closed:
			return
		if select.select([], [self.handler.wfile], [], 0)[1]:
			with self.lock:
				self.handler.wfile.write(b'\x88\x00')
		self.handler.wfile.flush()
		self.on_closed()

	def send_message(self, opcode, message):
		"""
		Send a message to the peer over the socket.

		:param int opcode: The opcode for the message to send.
		:param bytes message: The message data to send.
		"""
		if not isinstance(message, bytes):
			message = message.encode('utf-8')
		length = len(message)
		if not select.select([], [self.handler.wfile], [], 0)[1]:
			self.logger.error('the socket is not ready for writing')
			self.close()
			return
		buffer = b''
		buffer += struct.pack('B', 0x80 + opcode)
		if length <= 125:
			buffer += struct.pack('B', length)
		elif 126 <= length <= 65535:
			buffer += struct.pack('>BH', 126, length)
		else:
			buffer += struct.pack('>BQ', 127, length)
		buffer += message
		self._last_sent_opcode = opcode
		self.lock.acquire()
		try:
			self.handler.wfile.write(buffer)
			self.handler.wfile.flush()
		except Exception:
			self.logger.error('an error occurred while sending a message', exc_info=True)
			self.close()
		finally:
			self.lock.release()

	def send_message_binary(self, message):
		return self.send_message(self._opcode_binary, message)

	def send_message_ping(self, message):
		return self.send_message(self._opcode_ping, message)

	def send_message_text(self, message):
		return self.send_message(self._opcode_text, message)

	def on_closed(self):
		"""
		A method that can be over ridden and is called after the web socket is
		closed.
		"""
		pass

	def on_connected(self):
		"""
		A method that can be over ridden and is called after the web socket is
		connected.
		"""
		pass

	def on_message(self, opcode, message):
		"""
		The primary dispatch function to handle incoming WebSocket messages.

		:param int opcode: The opcode of the message that was received.
		:param bytes message: The data contained within the message.
		"""
		self.logger.debug("processing {0} (opcode: 0x{1:02x}) message".format(self._opcode_names.get(opcode, 'UNKNOWN'), opcode))
		if opcode == self._opcode_close:
			self.close()
		elif opcode == self._opcode_ping:
			if len(message) > 125:
				self.close()
				return
			self.send_message(self._opcode_pong, message)
		elif opcode == self._opcode_pong:
			pass
		elif opcode == self._opcode_binary:
			self.on_message_binary(message)
		elif opcode == self._opcode_text:
			try:
				message = self._decode_string(message)
			except UnicodeDecodeError:
				self.logger.warning('closing connection due to invalid unicode within a text message')
				self.close()
			else:
				self.on_message_text(message)
		elif opcode == self._opcode_continue:
			self.close()
		else:
			self.logger.warning("received unknown opcode: {0} (0x{0:02x})".format(opcode))
			self.close()

	def on_message_binary(self, message):
		"""
		A method that can be over ridden and is called when a binary message is
		received from the peer.

		:param bytes message: The message data.
		"""
		pass

	def on_message_text(self, message):
		"""
		A method that can be over ridden and is called when a text message is
		received from the peer.

		:param str message: The message data.
		"""
		pass

	def ping(self):
		self.send_message_ping(random_string(16))

class Serializer(object):
	"""
	This class represents a serilizer object for use with the RPC system.
	"""
	def __init__(self, name, charset='UTF-8', compression=None):
		"""
		:param str name: The name of the serializer to use.
		:param str charset: The name of the encoding to use.
		:param str compression: The compression library to use.
		"""
		if not name in g_serializer_drivers:
			raise ValueError("unknown serializer '{0}'".format(name))
		self.name = name
		self._charset = charset
		self._compression = compression
		self.content_type = "{0}; charset={1}".format(self.name, self._charset)
		if self._compression:
			self.content_type += '; compression=' + self._compression

	@classmethod
	def from_content_type(cls, content_type):
		"""
		Build a serializer object from a MIME Content-Type string.

		:param str content_type: The Content-Type string to parse.
		:return: A new serializer instance.
		:rtype: :py:class:`.Serializer`
		"""
		name = content_type
		options = {}
		if ';' in content_type:
			name, options_str = content_type.split(';', 1)
			for part in options_str.split(';'):
				part = part.strip()
				if '=' in part:
					key, value = part.split('=')
				else:
					key, value = (part, None)
				options[key] = value
		# old style compatibility
		if name.endswith('+zlib'):
			options['compression'] = 'zlib'
			name = name[:-5]
		return cls(name, charset=options.get('charset', 'UTF-8'), compression=options.get('compression'))

	def dumps(self, data):
		"""
		Serialize a python data type for transmission or storage.

		:param data: The python object to serialize.
		:return: The serialized representation of the object.
		:rtype: bytes
		"""
		data = g_serializer_drivers[self.name]['dumps'](data)
		if sys.version_info[0] == 3 and isinstance(data, str):
			data = data.encode(self._charset)
		if self._compression == 'zlib':
			data = zlib.compress(data)
		assert isinstance(data, bytes)
		return data

	def loads(self, data):
		"""
		Deserialize the data into it's original python object.

		:param bytes data: The serialized object to load.
		:return: The original python object.
		"""
		if not isinstance(data, bytes):
			raise TypeError("loads() argument 1 must be bytes, not {0}".format(type(data).__name__))
		if self._compression == 'zlib':
			data = zlib.decompress(data)
		if sys.version_info[0] == 3 and self.name.startswith('application/'):
			data = data.decode(self._charset)
		data = g_serializer_drivers[self.name]['loads'](data, (self._charset if sys.version_info[0] == 3 else None))
		if isinstance(data, list):
			data = tuple(data)
		return data

class AdvancedHTTPServer(object):
	"""
	This is the primary server class for the AdvancedHTTPServer module.
	Custom servers must inherit from this object to be compatible. When
	no *address* parameter is specified the address '0.0.0.0' is used and
	the port is guessed based on if the server is run as root or not and
	SSL is used.
	"""
	def __init__(self, handler_klass, address=None, addresses=None, use_threads=True, ssl_certfile=None, ssl_keyfile=None, ssl_version=None):
		"""
		:param handler_klass: The request handler class to use.
		:type handler_klass: :py:class:`.RequestHandler`
		:param tuple address: The address to bind to in the format (host, port).
		:param tuple addresses: The addresses to bind to in the format (host, port, ssl).
		:param bool use_threads: Whether to enable the use of a threaded handler.
		:param str ssl_certfile: An SSL certificate file to use, setting this enables SSL.
		:param str ssl_keyfile: An SSL certificate file to use.
		:param ssl_version: The SSL protocol version to use.
		"""
		if addresses is None:
			addresses = []
		if address is None and len(addresses) == 0:
			if ssl_certfile is not None:
				if os.getuid():
					addresses.insert(0, ('0.0.0.0', 8443, True))
				else:
					addresses.insert(0, ('0.0.0.0', 443, True))
			else:
				if os.getuid():
					addresses.insert(0, ('0.0.0.0', 8080, False))
				else:
					addresses.insert(0, ('0.0.0.0', 80, False))
		elif address:
			addresses.insert(0, (address[0], address[1], ssl_certfile is not None))
		self.ssl_certfile = ssl_certfile
		self.ssl_keyfile = ssl_keyfile
		if not hasattr(self, 'logger'):
			self.logger = logging.getLogger('AdvancedHTTPServer')
		self.__should_stop = threading.Event()
		self.__is_shutdown = threading.Event()
		self.__is_shutdown.set()
		self.__is_running = threading.Event()
		self.__is_running.clear()
		self.__server_thread = None
		self.__wakeup_fd = None

		self.__config = {
			'basic_auth': None,
			'robots_txt': b'User-agent: *\nDisallow: /\n',
			'serve_files': False,
			'serve_files_list_directories': True, # irrelevant if serve_files == False
			'serve_files_root': os.getcwd(),
			'serve_robots_txt': True,
			'server_version': 'AdvancedHTTPServer/' + __version__
		}

		self.sub_servers = []
		"""The instances of :py:class:`.ServerNonThreaded` that are responsible for listening on each configured address."""
		if use_threads:
			server_klass = ServerThreaded
		else:
			server_klass = ServerNonThreaded

		for address in addresses:
			server = server_klass((address[0], address[1]), handler_klass, config=self.__config)
			use_ssl = (len(address) == 3 and address[2])
			server.using_ssl = use_ssl
			self.sub_servers.append(server)
			self.logger.info("listening on {0}:{1}".format(address[0], address[1]) + (' with ssl' if use_ssl else ''))

		self._ssl_sni_ctxs = None
		if any([server.using_ssl for server in self.sub_servers]):
			self._ssl_sni_ctxs = {}
			if ssl_version is None or isinstance(ssl_version, str):
				ssl_version = resolve_ssl_protocol_version(ssl_version)
			self._ssl_ctx = ssl.SSLContext(ssl_version)
			self._ssl_ctx.load_cert_chain(ssl_certfile, keyfile=ssl_keyfile)
			if g_ssl_has_server_sni:
				self._ssl_ctx.set_servername_callback(self._ssl_servername_callback)
			for server in self.sub_servers:
				if not server.using_ssl:
					continue
				server.socket = self._ssl_ctx.wrap_socket(server.socket, server_side=True)

		if hasattr(handler_klass, 'custom_authentication'):
			self.logger.debug('a custom authentication function is being used')
			self.auth_set(True)

	def _ssl_servername_callback(self, sock, hostname, context):
		new_context = self._ssl_sni_ctxs.get(hostname)
		if new_context is None:
			return None
		sock.context = new_context
		return None

	def add_sni_cert(self, hostname, ssl_certfile=None, ssl_keyfile=None, ssl_version=None):
		"""
		Add an SSL certificate for a specific hostname as supported by SSL's
		server name indicator extension. See :rfc:`3546` for more details on
		SSL extensions. In order to use this method, the server instance must
		have been initialized with at least one address configured for SSL.

		:param str hostname: The hostname for this configuration.
		:param str ssl_certfile: An SSL certificate file to use, setting this enables SSL.
		:param str ssl_keyfile: An SSL certificate file to use.
		:param ssl_version: The SSL protocol version to use.
		"""
		if not g_ssl_has_server_sni:
			raise RuntimeError('the ssl server name indicator extension is unavailable')
		if self._ssl_sni_ctxs is None:
			raise RuntimeError('ssl was not enabled on initialization')
		if ssl_version is None or isinstance(ssl_version, str):
			ssl_version = resolve_ssl_protocol_version(ssl_version)
		ssl_ctx = ssl.SSLContext(ssl_version)
		ssl_ctx.load_cert_chain(ssl_certfile, keyfile=ssl_keyfile)
		self._ssl_sni_ctxs[hostname] = ssl_ctx

	@property
	def server_started(self):
		return self.__server_thread is not None

	def serve_forever(self, fork=False):
		"""
		Start handling requests. This method must be called and does not
		return unless the :py:meth:`.shutdown` method is called from
		another thread.

		:param bool fork: Whether to fork or not before serving content.
		:return: The child processes PID if *fork* is set to True.
		:rtype: int
		"""
		if fork:
			if not hasattr(os, 'fork'):
				raise OSError('os.fork is not available')
			child_pid = os.fork()
			if child_pid != 0:
				self.logger.info('forked child process: ' + str(child_pid))
				return child_pid
		self.__server_thread = threading.current_thread()
		self.__wakeup_fd = WakeupFd()
		self.__is_shutdown.clear()
		self.__should_stop.clear()
		self.__is_running.set()
		while not self.__should_stop.is_set():
			try:
				read_ready, _, _ = select.select([self.__wakeup_fd] + self.sub_servers, [], [])
				for server in read_ready:
					if isinstance(server, http.server.HTTPServer):
						server.handle_request()
			except socket.error:
				self.logger.warning('encountered socket error, stopping server')
				self.__should_stop.set()
		self.__is_shutdown.set()
		self.__is_running.clear()
		return 0

	def shutdown(self):
		"""Shutdown the server and stop responding to requests."""
		self.__should_stop.set()
		if self.__server_thread == threading.current_thread():
			self.__is_shutdown.set()
			self.__is_running.clear()
		else:
			if self.__wakeup_fd is not None:
				os.write(self.__wakeup_fd.write_fd, b'\x00')
			self.__is_shutdown.wait()
		if self.__wakeup_fd is not None:
			self.__wakeup_fd.close()
			self.__wakeup_fd = None
		for server in self.sub_servers:
			server.shutdown()

	@property
	def serve_files(self):
		"""
		Whether to enable serving files or not.

		:type: bool
		"""
		return self.__config['serve_files']

	@serve_files.setter
	def serve_files(self, value):
		value = bool(value)
		if self.__config['serve_files'] == value:
			return
		self.__config['serve_files'] = value
		if value:
			self.logger.info('serving files has been enabled')
		else:
			self.logger.info('serving files has been disabled')

	@property
	def serve_files_root(self):
		"""
		The web root to use when serving files.

		:type: str
		"""
		return self.__config['serve_files_root']

	@serve_files_root.setter
	def serve_files_root(self, value):
		self.__config['serve_files_root'] = os.path.abspath(value)

	@property
	def serve_files_list_directories(self):
		"""
		Whether to list the contents of directories. This is only honored
		when :py:attr:`.serve_files` is True.

		:type: bool
		"""
		return self.__config['serve_files_list_directories']

	@serve_files_list_directories.setter
	def serve_files_list_directories(self, value):
		self.__config['serve_files_list_directories'] = bool(value)

	@property
	def serve_robots_txt(self):
		"""
		Whether to serve a default robots.txt file which denies everything.

		:type: bool
		"""
		return self.__config['serve_robots_txt']

	@serve_robots_txt.setter
	def serve_robots_txt(self, value):
		self.__config['serve_robots_txt'] = bool(value)

	@property
	def server_version(self):
		"""
		The server version to be sent to clients in headers.

		:type: str
		"""
		return self.__config['server_version']

	@server_version.setter
	def server_version(self, value):
		self.__config['server_version'] = str(value)

	def auth_set(self, status):
		"""
		Enable or disable requiring authentication on all incoming requests.

		:param bool status: Whether to enable or disable requiring authentication.
		"""
		if not bool(status):
			self.__config['basic_auth'] = None
			self.logger.info('basic authentication has been disabled')
		else:
			self.__config['basic_auth'] = {}
			self.logger.info('basic authentication has been enabled')

	def auth_delete_creds(self, username=None):
		"""
		Delete the credentials for a specific username if specified or all
		stored credentials.

		:param str username: The username of the credentials to delete.
		"""
		if not username:
			self.__config['basic_auth'] = {}
			self.logger.info('basic authentication database has been cleared of all entries')
			return
		del self.__config['basic_auth'][username]

	def auth_add_creds(self, username, password, pwtype='plain'):
		"""
		Add a valid set of credentials to be accepted for authentication.
		Calling this function will automatically enable requiring
		authentication. Passwords can be provided in either plaintext or
		as a hash by specifying the hash type in the *pwtype* argument.

		:param str username: The username of the credentials to be added.
		:param password: The password data of the credentials to be added.
		:type password: bytes, str
		:param str pwtype: The type of the *password* data, (plain, md5, sha1, etc.).
		"""
		if not isinstance(password, (bytes, str)):
			raise TypeError("auth_add_creds() argument 2 must be bytes or str, not {0}".format(type(password).__name__))
		pwtype = pwtype.lower()
		if not pwtype in ('plain', 'md5', 'sha1', 'sha256', 'sha384', 'sha512'):
			raise ValueError('invalid password type, must be \'plain\', or supported by hashlib')
		if self.__config.get('basic_auth') is None:
			self.__config['basic_auth'] = {}
			self.logger.info('basic authentication has been enabled')
		if pwtype != 'plain':
			algorithms_available = getattr(hashlib, 'algorithms_available', ()) or getattr(hashlib, 'algorithms', ())
			if not pwtype in algorithms_available:
				raise ValueError('hashlib does not support the desired algorithm')
			# only md5 and sha1 hex for backwards compatibility
			if pwtype == 'md5' and len(password) == 32:
				password = binascii.unhexlify(password)
			elif pwtype == 'sha1' and len(password) == 40:
				password = binascii.unhexlify(password)
			if not isinstance(password, bytes):
				password = password.encode('UTF-8')
			if len(hashlib.new(pwtype, b'foobar').digest()) != len(password):
				raise ValueError('the length of the password hash does not match the type specified')
		self.__config['basic_auth'][username] = {'value': password, 'type': pwtype}

class ServerTestCase(unittest.TestCase):
	"""
	A base class for unit tests with AdvancedHTTPServer derived classes.
	"""
	server_class = AdvancedHTTPServer
	"""The :py:class:`.AdvancedHTTPServer` class to use as the server, this can be overridden by subclasses."""
	handler_class = RequestHandler
	"""The :py:class:`.RequestHandler` class to use as the request handler, this can be overridden by subclasses."""
	def __init__(self, *args, **kwargs):
		super(ServerTestCase, self).__init__(*args, **kwargs)
		self.test_resource = "/{0}".format(random_string(40))
		"""
		A resource which has a handler set to it which will respond with
		a 200 status code and the message 'Hello World!'
		"""
		self.server_address = ('localhost', random.randint(30000, 50000))
		self._server_kwargs = {
			'address': self.server_address
		}
		if hasattr(self, 'assertRegexpMatches') and not hasattr(self, 'assertRegexMatches'):
			self.assertRegexMatches = self.assertRegexpMatches
		if hasattr(self, 'assertRaisesRegexp') and not hasattr(self, 'assertRaisesRegex'):
			self.assertRaisesRegex = self.assertRaisesRegexp

	def setUp(self):
		RegisterPath("^{0}$".format(self.test_resource[1:]), self.handler_class.__name__)(self._test_resource_handler)
		self.server = self.server_class(self.handler_class, **self._server_kwargs)
		self.assertTrue(isinstance(self.server, AdvancedHTTPServer))
		self.server_thread = threading.Thread(target=self.server.serve_forever)
		self.server_thread.daemon = True
		self.server_thread.start()
		self.assertTrue(self.server_thread.is_alive())
		self.shutdown_requested = False
		if len(self.server_address) == 3 and self.server_address[2]:
			context = ssl.create_default_context()
			context.check_hostname = False
			context.verify_mode = ssl.CERT_NONE
			self.http_connection = http.client.HTTPSConnection(self.server_address[0], self.server_address[1], context=context)
		else:
			self.http_connection = http.client.HTTPConnection(self.server_address[0], self.server_address[1])
		self.http_connection.connect()

	def _test_resource_handler(self, handler, query):
		del query
		handler.send_response_full(b'Hello World!\n')
		return

	def assertHTTPStatus(self, http_response, status):
		"""
		Check an HTTP response object and ensure the status is correct.

		:param http_response: The response object to check.
		:type http_response: :py:class:`http.client.HTTPResponse`
		:param int status: The status code to expect for *http_response*.
		"""
		self.assertTrue(isinstance(http_response, http.client.HTTPResponse))
		error_message = "HTTP Response received status {0} when {1} was expected".format(http_response.status, status)
		self.assertEqual(http_response.status, status, msg=error_message)

	def http_request(self, resource, method='GET', headers=None):
		"""
		Make an HTTP request to the test server and return the response.

		:param str resource: The resource to issue the request to.
		:param str method: The HTTP verb to use (GET, HEAD, POST etc.).
		:param dict headers: The HTTP headers to provide in the request.
		:return: The HTTP response object.
		:rtype: :py:class:`http.client.HTTPResponse`
		"""
		headers = (headers or {})
		if not 'Connection' in headers:
			headers['Connection'] = 'keep-alive'
		self.http_connection.request(method, resource, headers=headers)
		time.sleep(0.025)
		response = self.http_connection.getresponse()
		response.data = response.read()
		return response

	def tearDown(self):
		if not self.shutdown_requested:
			self.assertTrue(self.server_thread.is_alive())
		self.http_connection.close()
		self.server.shutdown()
		self.server_thread.join(10.0)
		self.assertFalse(self.server_thread.is_alive())
		del self.server

def main():
	try:
		server = build_server_from_argparser()
	except ImportError:
		server = AdvancedHTTPServer(RequestHandler, use_threads=False)
		server.serve_files_root = '.'

	server.serve_files_root = (server.serve_files_root or '.')
	server.serve_files = True
	try:
		server.serve_forever()
	except KeyboardInterrupt:
		pass
	server.shutdown()
	logging.shutdown()
	return 0

if __name__ == '__main__':
	main()
