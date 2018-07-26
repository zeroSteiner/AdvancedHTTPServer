#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  redirect.py
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

import argparse
import logging
import sys

from advancedhttpserver import *
from advancedhttpserver import __version__

class RedirectHandler(RequestHandler):
	target_url = 'http://127.0.0.1'
	def on_init(self):
		self.handler_map['.*'] = self.redirect

	def redirect(self, query):
		print(self.path)
		self.send_response(302)
		self.send_header('Location', self.target_url)
		self.end_headers()
		return

def main():
	parser = argparse.ArgumentParser(description='AdvancedHTTPServer Redirect', conflict_handler='resolve')
	parser.add_argument('target_url', help='the url to redirect to')
	arguments = parser.parse_args()

	RedirectHandler.target_url = arguments.target_url
	print("AdvancedHTTPServer version: {0}".format(__version__))
	print('Redirecting to: ' + arguments.target_url)
	logging.getLogger('').setLevel(logging.DEBUG)
	console_log_handler = logging.StreamHandler()
	console_log_handler.setLevel(logging.INFO)
	console_log_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-8s %(message)s"))
	logging.getLogger('').addHandler(console_log_handler)

	server = AdvancedHTTPServer(RedirectHandler)
	try:
		server.serve_forever()
	except KeyboardInterrupt:
		server.shutdown()
	return 0

if __name__ == '__main__':
	main()
