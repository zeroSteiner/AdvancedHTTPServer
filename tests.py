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

import httplib
import logging
import os
import unittest

from AdvancedHTTPServer import AdvancedHTTPServerTestCase, random_string

if hasattr(logging, 'NullHandler'):
	null_handler = logging.NullHandler()
else:
	null_handler = logging.StreamHandler(open(os.devnull, 'w'))
logging.getLogger('AdvancedHTTPServer').addHandler(null_handler)

class AdvancedHTTPServerTests(AdvancedHTTPServerTestCase):
	def test_authentication(self):
		username = random_string(8)
		password = random_string(12)
		self.server.auth_add_creds(username, password)
		response = self.http_request(self.test_resource, 'GET')
		self.assertHTTPStatus(response, 401)
		response = self.http_request(self.test_resource, 'HEAD')
		self.assertHTTPStatus(response, 401)
		response = self.http_request(self.test_resource, 'POST')
		self.assertHTTPStatus(response, 401)
		auth_headers = {'Authorization': 'Basic ' + "{0}:{1}".format(username, password).encode('base64')}
		response = self.http_request(self.test_resource, 'GET', headers=auth_headers)
		self.assertHTTPStatus(response, 200)
		self.server.auth_set(False)
		response = self.http_request(self.test_resource, 'GET')
		self.assertHTTPStatus(response, 200)

	def test_authentication_bad_credentials(self):
		self.server.auth_add_creds(random_string(8), random_string(12))
		auth_headers = {'Authorization': 'Basic ' + "{0}:{1}".format(random_string(8), random_string(12)).encode('base64')}
		response = self.http_request(self.test_resource, 'GET', headers=auth_headers)
		self.assertHTTPStatus(response, 401)

	def test_fake_resource(self):
		response = self.http_request('/' + random_string(30), 'GET')
		self.assertHTTPStatus(response, 404)
		response = self.http_request('/' + random_string(30), 'POST')
		self.assertHTTPStatus(response, 404)

	def test_verb_fake(self):
		response = self.http_request(self.test_resource, 'FAKE')
		self.assertHTTPStatus(response, 501)

	def test_verb_get(self):
		response = self.http_request(self.test_resource, 'GET')
		self.assertHTTPStatus(response, 200)
		self.assertTrue('Hello World!' in response.read())

	def test_verb_head(self):
		response = self.http_request(self.test_resource, 'HEAD')
		self.assertHTTPStatus(response, 200)
		self.assertTrue(len(response.read()) == 0)

if __name__ == '__main__':
	unittest.main()
