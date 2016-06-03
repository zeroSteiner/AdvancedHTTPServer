#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  websockets.py
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

import logging

from advancedhttpserver import *
from advancedhttpserver import __version__

class DemoWebSocketHandler(WebSocketHandler):
	def on_message_binary(self, message):
		self.send_message(self._opcode_binary, message)

	def on_message_text(self, message):
		print(message)
		self.send_message(self._opcode_text, message)

class DemoHandler(RequestHandler):
	web_socket_handler = DemoWebSocketHandler

def main():
	print("AdvancedHTTPServer version: {0}".format(__version__))
	logging.getLogger('').setLevel(logging.DEBUG)
	console_log_handler = logging.StreamHandler()
	console_log_handler.setLevel(logging.DEBUG)
	console_log_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-8s %(message)s"))
	logging.getLogger('').addHandler(console_log_handler)

	server = AdvancedHTTPServer(DemoHandler, address=('', 9001))
	server.server_version = 'AdvancedHTTPServerDemo'
	try:
		server.serve_forever()
	except KeyboardInterrupt:
		server.shutdown()
	return 0

if __name__ == '__main__':
	main()
