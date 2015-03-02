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
import time
import unittest

from AdvancedHTTPServer import AdvancedHTTPServerRegisterPath
from AdvancedHTTPServer import AdvancedHTTPServerRPCClient
from AdvancedHTTPServer import AdvancedHTTPServerRPCClientCached
from AdvancedHTTPServer import AdvancedHTTPServerRPCError
from AdvancedHTTPServer import AdvancedHTTPServerSerializer
from AdvancedHTTPServer import AdvancedHTTPServerTestCase
from AdvancedHTTPServer import has_msgpack
from AdvancedHTTPServer import random_string
from AdvancedHTTPServer import resolve_ssl_protocol_version

if hasattr(logging, 'NullHandler'):
	null_handler = logging.NullHandler()
else:
	null_handler = logging.StreamHandler(open(os.devnull, 'w'))
logging.getLogger('AdvancedHTTPServer').addHandler(null_handler)

class AdvancedHTTPServerTests(AdvancedHTTPServerTestCase):
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

	def _rpc_test_double_handler(self, value):
		return value * 2

	def _rpc_test_datetime_handler(self):
		return datetime.datetime.now()

	def _rpc_test_throw_exception(self):
		raise RuntimeError('this is an error!')

	def setUp(self):
		self.rpc_test_double = "{0}".format(random_string(40))
		self.rpc_test_datetime = "{0}".format(random_string(40))
		self.rpc_test_throw_exception = "{0}".format(random_string(40))
		AdvancedHTTPServerRegisterPath("/{0}".format(self.rpc_test_double), self.handler_class.__name__, is_rpc=True)(self._rpc_test_double_handler)
		AdvancedHTTPServerRegisterPath("/{0}".format(self.rpc_test_datetime), self.handler_class.__name__, is_rpc=True)(self._rpc_test_datetime_handler)
		AdvancedHTTPServerRegisterPath("/{0}".format(self.rpc_test_throw_exception), self.handler_class.__name__, is_rpc=True)(self._rpc_test_throw_exception)
		super(AdvancedHTTPServerTests, self).setUp()

	def build_rpc_client(self, username=None, password=None, hmac_key=None, cached=False):
		if cached:
			klass = AdvancedHTTPServerRPCClientCached
		else:
			klass = AdvancedHTTPServerRPCClient
		return klass(self.server_address, username=username, password=password, hmac_key=hmac_key)

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
		response_data = response.read()
		self.assertEqual(b'User-agent: *\nDisallow: /\n', response_data)
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
		self.assertRaisesRegex(AdvancedHTTPServerRPCError, r'the server responded with 401 \'Unauthorized\'', self.run_rpc_tests, rpc)
		rpc = self.build_rpc_client(username=username, password=random_string(12))
		self.assertRaisesRegex(AdvancedHTTPServerRPCError, r'the server responded with 401 \'Unauthorized\'', self.run_rpc_tests, rpc)
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

	def test_rpc_hmac(self):
		hmac = random_string(16)
		self.server.rpc_hmac_key = hmac
		rpc = self.build_rpc_client()
		self.assertRaisesRegex(AdvancedHTTPServerRPCError, r'the server responded with 401 \'Unauthorized\'', self.run_rpc_tests, rpc)
		rpc = self.build_rpc_client(hmac_key=random_string(16))
		self.assertRaisesRegex(AdvancedHTTPServerRPCError, r'the server responded with 401 \'Unauthorized\'', self.run_rpc_tests, rpc)
		rpc = self.build_rpc_client(hmac_key=hmac)
		self.run_rpc_tests(rpc)

	def test_serializer_build(self):
		serializer = AdvancedHTTPServerSerializer.from_content_type('application/json')
		self.assertIsInstance(serializer, AdvancedHTTPServerSerializer)
		self.assertEqual(serializer.name, 'application/json')

	def test_serializer_json(self):
		serializer = AdvancedHTTPServerSerializer('application/json')
		self._test_serializer_hooks(serializer)

	@unittest.skipUnless(has_msgpack, 'this test requires msgpack')
	def test_serializer_msgpack(self):
		serializer = AdvancedHTTPServerSerializer('binary/message-pack')
		self._test_serializer_hooks(serializer)

	def test_verb_fake(self):
		response = self.http_request(self.test_resource, 'FAKE')
		self.assertHTTPStatus(response, 501)

	def test_verb_get(self):
		response = self.http_request(self.test_resource, 'GET')
		self.assertHTTPStatus(response, 200)
		response_data = response.read()
		self.assertTrue(b'Hello World!' in response_data)

	def test_verb_head(self):
		response = self.http_request(self.test_resource, 'HEAD')
		self.assertHTTPStatus(response, 200)
		self.assertTrue(len(response.read()) == 0)

	def test_verb_options(self):
		response = self.http_request(self.test_resource, 'OPTIONS')
		self.assertHTTPStatus(response, 200)
		self.assertTrue(len(response.read()) == 0)
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
		with self.assertRaisesRegex(AdvancedHTTPServerRPCError, '^a remote exception occurred$'):
			rpc(self.rpc_test_throw_exception)

if __name__ == '__main__':
	unittest.main()
