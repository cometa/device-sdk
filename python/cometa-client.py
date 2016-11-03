#!/usr/bin/env python
"""
Author: Emile Camus
"""
__license__ = """
Copyright 2015 Visible Energy Inc.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import cometa
import time
import sys, getopt
import string
import json
import subprocess

from uuid import getnode as get_mac
from time import gmtime, strftime

def get_mac_address():
	"""
		Return an hex string with the current network interface MAC address.
	"""
	mac = ''
	m = get_mac()
	for i in range(0, 12, 2):
		mac += ("%012X" % m)[i:i+2]
	return mac

def message_handler(msg, msg_len):
	"""
		The message handler is the Cometa receive callback. 
		Every time the Cometa library receives a message for this device the message_handler is invoked.
	"""
	try:
		c = json.loads(msg)
	except Exception, e:
		print "Error in parsing the message: ", msg
		return "{\"msg\":\"Invalid JSON object.\"}"

	if 'cmd' in c:
		print "Command received: ", c['cmd']	#DEBUG
		command = c['cmd']
		# execute the command in a shell on the device
		try:
			subprocess.check_call(command,shell=True)
			out = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE).stdout.read()
			return out
		except Exception, e:
			print e
			return "{\"msg\":\"Invalid command.\"}"
	else:
		print "Invalid command."
		return "{\"msg\":\"Invalid command.\"}"
	
def main(argv):
	"""
		Stand-alone Cometa client application. This application is a sample of a device in the Cometa cloud infrastructure. 
		Running this application on a device, makes the device accessible remotely using the Cometa HTTP API and Websockets interface.

		The application implements a simple wire protocol with one type of message with the following payload:
			{"cmd":"<shell command>"}
		All the messages that conform to the above format are processed by executing the <shell command> in the host machine
		with the output of the <shell command> returned to the caller in the response.

	 	 Command line parameters:
	 		-s 	: Cometa server name {COMETA_SERVER}
	 		-p 	: Cometa server port {COMETA_PORT}
	 		-a 	: Cometa application ID to attach the device to (as defined in the Cometa server /etc/cometa.conf)
	  		-d 	: the device ID (optional). If not specified, the machine's MAC address is used as device_id

	  	Each device that connects to a Cometa server, is attached to an "application" that is defined in the Cometa configuration
	  	file /etc/cometa.conf in the server. A Cometa "application" is identified by the {Application_ID} and has an {Application_Secret}.
	  	The {Application_ID} is the equivalent of an API key, and the {Application_Secret} is an authorization token needed by an
	  	application to access a remote device attached to Cometa.

	  	Once this application is running on a device, and it has successfully attached to a Cometa server, the HTTP <send> command is used
	  	to execute the <shell command> on the device identified by {DEVICE_ID}:

	  		curl -X POST -d '{"cmd":<shell command>'}' -H 'Authorization: OAuth {Application_Secret}>' \
	  			http://{COMETA_SERVER}:{COMETA_PORT}/v1/applications/{Application_ID}/devices/{DEVICE_ID}/send

	  	Check the Cometa API documentation at http://www.cometa.io/cometa-api.html for further details on the HTTP commands and 
	  	for a description of how to obtain a Websocket endpoint for the remote device.

	  	IMPORTANT: Use port 443 to enable SSL.
	"""
	cometa_server = '' 
	cometa_port = 0  
	application_id = '' 
	# if not specified use the machine's MAC address as Cometa device ID
	device_id = get_mac_address()

	try:
		opts, args = getopt.getopt(argv,"d:s:p:a:")
	except getopt.GetoptError:
		print 'cometa-client.py -s <cometa_server> -p <cometa_port> -a <application_id> [-d <device_id>]'
		sys.exit(2)
	for opt, arg in opts:
		if opt == "-d":
			device_id = arg
		elif opt == "-s":
			cometa_server = arg
		elif opt == "-p":
			cometa_port = string.atoi(arg)
		elif opt == "-a":
			application_id = arg

	if application_id == '' or cometa_server == '' or cometa_port == 0:
		print 'Usage: cometa-client.py -s <cometa_server> -p <cometa_port> -a <application_id> [-d <device_id>]'
		sys.exit(2)

	# ------------------------------------------------ #
	print "Cometa client started.\r\nParams: cometa_server:", cometa_server, "cometa_port:", cometa_port, "application_id:", application_id, "device_id:", device_id

	# Instantiate a Cometa object
	com = cometa.CometaClient(cometa_server, cometa_port, application_id)
	# Set debug flag
	com.debug = True

	# Bind the message_handler() callback. The callback is doing the function of respoding
	# to remote requests and handling the core part of the work of the application.
	com.bind_cb(message_handler)

	# Attach the device to Cometa.
	ret = com.attach(device_id, "stardust")
	if com.error != 0:
		print "(FATAL) Error in attaching to Cometa.", com.perror()
		sys.exit(2)

	# When attach is successful the server returns an object of the format:
	# {"msg":"200 OK","heartbeat":60,"timestamp":1441405206}
	try:
		ret_obj = json.loads(ret)
	except Exception, e:
		print "(FATAL) Error in parsing the message returned after attaching to Cometa. Message:", ret
		sys.exit(2)

	print "Device [%s] attached to Cometa. Server timestamp: %d" % (device_id, ret_obj['timestamp'])
	if com.debug:
		print "Server returned:", ret

	# Application main loop.
	while True:
		"""
			Send a data event with the device ID and the current time upstream to the Cometa
			server every minute. This is to demonstrate use of the asynchronous data event messages.
			Once a data event message is received by Cometa, the message is propagated to all opened 
			device Websockets. If a Webhook for the application is specified in the Cometa configuration
			file /etc/cometa.conf the message is also posted to the configured Webhook.
		"""
		time.sleep(60)
		now = strftime("%Y-%m-%d %H:%M:%S", gmtime())
		msg = "{\"id\":\"%s\",\"time\":\"%s\"}" % (device_id, now)

		if com.send_data(msg) < 0:
			print "Error in sending data."
		else:
			if com.debug:
				print "sending data event.", msg

	print "***** should never get here"

if __name__ == "__main__":
    main(sys.argv[1:])