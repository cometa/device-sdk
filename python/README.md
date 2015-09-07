Python Cometa Library
=============
The library is providing the Cometa class and methods used to connect a device to the Cometa cloud infrastructure 
and to handle remote interactions with the device.

The Cometa cloud infrastructure allows to send remote devices messages and to receive synchronous responses in the
tpyical RPC pattern. The library provides a way to use a callback to handle incoming requests and to send responses.

Also, the library is used to send asynchronous event data messages upstream to the Cometa server. The event data messages
are propagated by Cometa to all open Websockets endpoints and are relayed to the configured Webhook for post-processing,
for instance enqueued in a real-time analytics pipeline.

After instantiating a Cometa object, a callback is bound to the connection and it is used to handle incoming messages 
for the device. The receive and dispatch loop is in a separate thread.

Also, the library implements the Cometa `heartbeat` function that is started as a separate thread.

The implementation takes advantage of the property of the Cometa server to send only one request at a time to a device and that messages without a response are not resent after the timeout. When a message is received by the device the previous request has been completed in the Cometa server. This way, the device application doesn't have to implement message queues or to address any synchronization between receive and send loops.

Check the [HTTP Cometa API documentation](http://www.cometa.io/cometa-api.html) for additional details.

Sample Application
-------

The `cometa-client.py` is a stand-alone Cometa device application that executes a shell command received in a Cometa message and returns the command's output in the response.

The application sends a timestamp to the server every 60 seconds to demonstrate the use of upstream data events.

Running this application on a device, makes the device accessible remotely using the Cometa HTTP API and Websockets interface.

The application implements a simple wire protocol with one type of message with the following payload:
	{"cmd":"<shell command>"}
All the messages that conform to the above format are processed by executing the <shell command> in the host machine
with the output of the <shell command> returned to the caller in the response.

Usage:

	cometa-client.py -s [server_name] -p [server_port] -a [app_id] {-d device_id}
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


Example
--- 
 		$ python cometa-client.py -s api.service.com -p 80 -k 946604ed1d981eca287 -d 777 

Once `cometa-client` runs on the device, a shell command can be sent as message to be remotely executed in the device and the output returned in the response. 

	$ curl -X POST -d '{"cmd":"/bin/cat /etc/hosts"}' -H 'Authorization: OAuth ba723dc4811d507580f4'  \
		http://devel.cometa.io:8000/v1/applications/846604ed0c981eca2779/devices/777/send
	
	127.0.0.1       localhost 
	127.0.1.1       kubuntu 

	# The following lines are desirable for IPv6 capable hosts 
	::1     ip6-localhost ip6-loopback 
	fe00::0 ip6-localnet 
	ff00::0 ip6-mcastprefix 
	ff02::1 ip6-allnodes 
	ff02::2 ip6-allrouters 
