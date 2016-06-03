#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  tests.py
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

import base64
import datetime
import hashlib
import logging
import os
import random
import ssl
import sys
import time
import unittest

from advancedhttpserver import AdvancedHTTPServer
from advancedhttpserver import RegisterPath
from advancedhttpserver import RPCClient
from advancedhttpserver import RPCClientCached
from advancedhttpserver import RPCError
from advancedhttpserver import Serializer
from advancedhttpserver import ServerTestCase
from advancedhttpserver import build_server_from_config
from advancedhttpserver import has_msgpack
from advancedhttpserver import random_string
from advancedhttpserver import resolve_ssl_protocol_version

if sys.version_info[0] < 3:
	import httplib
	http = type('http', (), {'client': httplib})
	from ConfigParser import ConfigParser
else:
	import http.client
	from configparser import ConfigParser

if hasattr(logging, 'NullHandler'):
	null_handler = logging.NullHandler()
else:
	null_handler = logging.StreamHandler(open(os.devnull, 'w'))
logging.getLogger('AdvancedHTTPServer').addHandler(null_handler)

ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE
test_certfile = os.path.join(os.path.dirname(__file__), 'advancedhttpserver.pem')

class ServerHTTPTests(ServerTestCase):
	def _test_authentication(self, username, password):
		response = self.http_request(self.test_resource, 'GET')
		self.assertHTTPStatus(response, 401)
		response = self.http_request(self.test_resource, 'HEAD')
		self.assertHTTPStatus(response, 401)
		response = self.http_request(self.test_resource, 'POST')
		self.assertHTTPStatus(response, 401)
		auth_headers = {'Authorization': 'Basic ' + base64.b64encode("{0}:{1}".format(username, password).encode('utf-8')).decode('utf-8')}
		response = self.http_request(self.test_resource, 'GET', headers=auth_headers)
		self.assertHTTPStatus(response, 200)
		self.server.auth_set(False)
		response = self.http_request(self.test_resource, 'GET')
		self.assertHTTPStatus(response, 200)

	def _test_serializer_obj(self, serializer, obj, klass):
		obj_encoded = serializer.dumps(obj)
		obj_decoded = serializer.loads(obj_encoded)
		self.assertTrue(obj_decoded.__class__ == klass)
		self.assertNotEqual(obj_encoded, obj_decoded)
		self.assertEqual(obj_decoded, obj)

	def _test_serializer_hooks(self, serializer):
		self._test_serializer_obj(serializer, datetime.datetime.utcnow(), datetime.datetime)
		self._test_serializer_obj(serializer, datetime.datetime.utcnow().date(), datetime.date)
		self._test_serializer_obj(serializer, datetime.datetime.utcnow().time(), datetime.time)

	def _rpc_test_double_handler(self, handler, value):
		return value * 2

	def _rpc_test_datetime_handler(self, handler):
		return datetime.datetime.now()

	def _rpc_test_throw_exception(self, handler):
		raise RuntimeError('this is an error!')

	def setUp(self):
		self.rpc_test_double = "{0}".format(random_string(40))
		self.rpc_test_datetime = "{0}".format(random_string(40))
		self.rpc_test_throw_exception = "{0}".format(random_string(40))
		RegisterPath("/{0}".format(self.rpc_test_double), self.handler_class.__name__, is_rpc=True)(self._rpc_test_double_handler)
		RegisterPath("/{0}".format(self.rpc_test_datetime), self.handler_class.__name__, is_rpc=True)(self._rpc_test_datetime_handler)
		RegisterPath("/{0}".format(self.rpc_test_throw_exception), self.handler_class.__name__, is_rpc=True)(self._rpc_test_throw_exception)
		super(ServerHTTPTests, self).setUp()

	def build_rpc_client(self, username=None, password=None, cached=False, use_ssl=False):
		if cached:
			klass = RPCClientCached
		else:
			klass = RPCClient
		rpc_client = klass(
			self.server_address,
			username=username,
			password=password,
			use_ssl=use_ssl,
			ssl_context=ssl_context
		)
		return rpc_client

	def test_authentication_hash(self):
		username = random_string(8)
		password = random_string(12)
		password_hash = hashlib.new('md5', password.encode('utf-8')).hexdigest()
		self.server.auth_add_creds(username, password_hash, 'md5')
		self._test_authentication(username, password)
		password_hash = hashlib.new('md5', password.encode('utf-8')).digest()
		self.server.auth_add_creds(username, password_hash, 'md5')
		self._test_authentication(username, password)

	def test_authentication_plain(self):
		username = random_string(8)
		password = random_string(12)
		self.server.auth_add_creds(username, password)
		self._test_authentication(username, password)

	def test_authentication_bad_credentials(self):
		self.server.auth_add_creds(random_string(8), random_string(12))
		auth_headers = {'Authorization': 'Basic ' + base64.b64encode("{0}:{1}".format(random_string(8), random_string(12)).encode('utf-8')).decode('utf-8')}
		response = self.http_request(self.test_resource, 'GET', headers=auth_headers)
		self.assertHTTPStatus(response, 401)

	def test_connection_close(self):
		headers = {'Connection': 'close'}

		response = self.http_request('/' + random_string(30), 'GET', headers=headers)
		self.assertHTTPStatus(response, 404)
		self.assertIsNone(self.http_connection.sock)

		response = self.http_request(self.test_resource, 'GET', headers=headers)
		self.assertHTTPStatus(response, 200)
		self.assertIsNone(self.http_connection.sock)

	def test_connection_keep_alive(self):
		headers = {'Connection': 'keep-alive'}

		response = self.http_request('/' + random_string(30), 'GET', headers=headers)
		self.assertHTTPStatus(response, 404)
		self.assertIsNotNone(self.http_connection.sock)

		response = self.http_request(self.test_resource, 'GET', headers=headers)
		self.assertHTTPStatus(response, 200)
		self.assertIsNotNone(self.http_connection.sock)

	def test_fake_resource(self):
		response = self.http_request('/' + random_string(30), 'GET')
		self.assertHTTPStatus(response, 404)
		response = self.http_request('/' + random_string(30), 'POST')
		self.assertHTTPStatus(response, 404)

	def test_resolve_ssl_protocol_version(self):
		default_version = resolve_ssl_protocol_version()
		self.assertTrue(isinstance(default_version, int))
		for version_constant in (a for a in dir(ssl) if a.startswith('PROTOCOL_')):
			version_name = version_constant[9:]
			version = getattr(ssl, version_constant)
			self.assertEqual(resolve_ssl_protocol_version(version_name), version)

	def test_robots_dot_text(self):
		response = self.http_request('/robots.txt', 'GET')
		self.assertHTTPStatus(response, 200)
		self.assertEqual(b'User-agent: *\nDisallow: /\n', response.data)
		self.server.serve_robots_txt = False
		response = self.http_request('/robots.txt', 'GET')
		self.assertHTTPStatus(response, 404)

	def test_rpc_basic(self):
		rpc = self.build_rpc_client()
		self.run_rpc_tests(rpc)

	@unittest.skipUnless(has_msgpack, 'this test requires msgpack')
	def test_rpc_msgpack(self):
		rpc = self.build_rpc_client()
		rpc.set_serializer('binary/message-pack')
		self.run_rpc_tests(rpc)

	def test_rpc_authentication(self):
		username = random_string(8)
		password = random_string(12)
		self.server.auth_add_creds(username, password)
		rpc = self.build_rpc_client()
		self.assertRaisesRegex(RPCError, r'the server responded with 401 \'Unauthorized\'', self.run_rpc_tests, rpc)
		rpc = self.build_rpc_client(username=username, password=random_string(12))
		self.assertRaisesRegex(RPCError, r'the server responded with 401 \'Unauthorized\'', self.run_rpc_tests, rpc)
		rpc = self.build_rpc_client(username=username, password=password)
		self.run_rpc_tests(rpc)

	def test_rpc_cached(self):
		rpc = self.build_rpc_client(cached=True)
		dt1 = rpc.cache_call(self.rpc_test_datetime)
		self.assertIsInstance(dt1, datetime.datetime)
		time.sleep(0.5)
		dt2 = rpc.cache_call(self.rpc_test_datetime)
		self.assertIsInstance(dt2, datetime.datetime)
		self.assertEqual(dt1, dt2)

	def test_rpc_compression(self):
		rpc = self.build_rpc_client()
		rpc.set_serializer('application/json', compression='zlib')
		self.run_rpc_tests(rpc)

	def test_serializer_build(self):
		serializer = Serializer.from_content_type('application/json')
		self.assertIsInstance(serializer, Serializer)
		self.assertEqual(serializer.name, 'application/json')

	def test_serializer_json(self):
		serializer = Serializer('application/json')
		self._test_serializer_hooks(serializer)

	@unittest.skipUnless(has_msgpack, 'this test requires msgpack')
	def test_serializer_msgpack(self):
		serializer = Serializer('binary/message-pack')
		self._test_serializer_hooks(serializer)

	def test_verb_fake(self):
		response = self.http_request(self.test_resource, 'FAKE')
		self.assertHTTPStatus(response, 501)

	def test_verb_get(self):
		response = self.http_request(self.test_resource, 'GET')
		self.assertHTTPStatus(response, 200)
		self.assertTrue(b'Hello World!' in response.data)

	def test_verb_head(self):
		response = self.http_request(self.test_resource, 'HEAD')
		self.assertHTTPStatus(response, 200)
		self.assertTrue(len(response.data) == 0)

	def test_verb_options(self):
		response = self.http_request(self.test_resource, 'OPTIONS')
		self.assertHTTPStatus(response, 200)
		self.assertTrue(len(response.data) == 0)
		allow_header = response.getheader('Allow')
		self.assertIsNotNone(allow_header)
		should_allow = set(['POST', 'HEAD', 'RPC', 'OPTIONS', 'GET'])
		real_allow = set(allow_header.split(', '))
		self.assertSetEqual(real_allow, should_allow)

	def run_rpc_tests(self, rpc):
		dt = rpc(self.rpc_test_datetime)
		self.assertIsInstance(dt, datetime.datetime)
		number = random.randint(0, 10000)
		doubled = rpc(self.rpc_test_double, number)
		self.assertEqual(doubled, number * 2)
		with self.assertRaisesRegex(RPCError, '^a remote exception occurred$'):
			rpc(self.rpc_test_throw_exception)

class ServerHTTPSTests(ServerHTTPTests):
	def __init__(self, *args, **kwargs):
		super(ServerHTTPSTests, self).__init__(*args, **kwargs)
		self._server_kwargs['ssl_certfile'] = test_certfile
		self.server_address = (self.server_address[0], self.server_address[1], True)

	def build_rpc_client(self, *args, **kwargs):
		kwargs['use_ssl'] = True
		return super(ServerHTTPSTests, self).build_rpc_client(*args, **kwargs)

class ServerBindHTTPTests(ServerTestCase):
	def __init__(self, *args, **kwargs):
		super(ServerBindHTTPTests, self).__init__(*args, **kwargs)
		self.addresses = (
			('127.0.0.1', random.randint(30000, 50000)),
			('127.0.0.1', random.randint(30000, 50000), False)
		)
		self.server_address = self.addresses[0]
		self._server_kwargs = {
			'addresses': self.addresses
		}

	def test_bind_multiple_ports(self):
		for address in self.addresses:
			self.http_connection.close()
			if len(address) == 3 and address[2]:
				self.http_connection = http.client.HTTPSConnection(address[0], address[1], context=ssl_context)
			else:
				self.http_connection = http.client.HTTPConnection(address[0], address[1])
			resp = self.http_request('/')
			self.assertHTTPStatus(resp, 404)

class ServerBindMixTests(ServerBindHTTPTests):
	def __init__(self, *args, **kwargs):
		super(ServerBindMixTests, self).__init__(*args, **kwargs)
		self.addresses = (
			('127.0.0.1', random.randint(30000, 50000), True),  # https
			('127.0.0.1', random.randint(30000, 50000), False)  # http
		)
		self.server_address = self.addresses[0]
		self._server_kwargs['addresses'] = self.addresses
		self._server_kwargs['ssl_certfile'] = test_certfile

class ServerBuildTests(unittest.TestCase):
	def test_build_from_config(self):
		config_section = random_string(8)
		config = ConfigParser()
		config.add_section(config_section)
		config.set(config_section, 'ip', '127.0.0.1')
		config.set(config_section, 'port', str(random.randint(30000, 50000)))
		server = build_server_from_config(config, config_section)
		self.assertIsInstance(server, AdvancedHTTPServer)

if __name__ == '__main__':
	unittest.main()
