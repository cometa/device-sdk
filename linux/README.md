Linux C library
==================

The library is for a generic Linux/Posix system and it is suitable for embedded systems with limited resources such as the Raspberry PI or the BeagleBone. No use of `malloc` and compact code.

All the function of this library are synchronous, that is they block until the requested operation is completed or an error or timeout occurs. 

A callback is used to handle incoming messages from the Cometa server and invoked by the receive loop that is in a separate thread.

The library implements the Cometa `heartbeat` function as a separate thread.

The implementation takes advantage of the property of the Cometa server to send only one request at a time to a device and that messages without a response are not resent after the timeout. When a message is received by the device the previous request has been completed in the Cometa server. This way, the device application doesn't have to implement message queues or to address any synchronization between receive and send loops.

The library uses the [Node HTTP Parser](https://github.com/joyent/http-parser) but given the limited use, it can be easily replaced by hand-crafted code.

Installation
-------
To build the (default) shared library and the samples use:

	./bootstrap
	./configure
	make

To install use:

	sudo make install

To enable additional debugging, uncomment and comment the relevant default CFLAGS definition in the configure.ac file to control the -DDEBUG option.

By default `WITH_SSL` is configured (the `rootcert.pem` CA root certificate used in the server needs to be copied into the same directory as the samples). As with the DEBUG manifest the configure.ac CFLAGS can be modified to disable SSL support if required.

Samples
-------

The `cometa-client` is a stand-alone cometa device application that executes a shell command received in a Cometa message and returns the command's output in the response.

The application sends a timestamp to the server every 60 seconds to demonstrate the use of upstream events.

Usage:

	cometa-client -s [server_name] -p [server_port] -a [app_id] {-d device_id} {-v} {-e}
		-s 	: Cometa server name (FQDN)
 		-p 	: Cometa server port
 		-a 	: Cometa application ID to attach the device to (defined in /etc/cometa.conf)
 		-d 	: the device ID. If not specified, the machine's MAC address is used as device_id
 		-e      : use SSL
 		-v for verbose (default is silent)
 
 	example 
 		$ ./cometa-client -s api.service.com -p 80 -a 946604ed1d981eca287 -d 777 -v
 		
	using SSL
		$ ./cometa-client -s api.service.com -p 443 -a 946604ed1d981eca287 -d 777 -v -e
		
Once `cometa-client` runs on the device, a shell command can be sent as message to be remotely executed in the device and the output returned in the response. 

	$ curl -X POST -d '/bin/cat /etc/hosts' -H 'Authorization: OAuth ba723dc4811d507580f4'  http://devel.cometa.io:8000/v1/applications/846604ed0c981eca2779/devices/777/send
	
	127.0.0.1       localhost 
	127.0.1.1       kubuntu 

	# The following lines are desirable for IPv6 capable hosts 
	::1     ip6-localhost ip6-loopback 
	fe00::0 ip6-localnet 
	ff00::0 ip6-mcastprefix 
	ff02::1 ip6-allnodes 
	ff02::2 ip6-allrouters 

Cometa C-language SDK
--------

**Files**

>libcometa.c
libcometa.h

```
/* 
 * Result codes for Cometa functions 
 */
typedef enum  {
    COMEATAR_OK,			/* success */
	COMEATAR_TIMEOUT,		/* time out before the request has completed */
	COMEATAR_NET_ERROR,		/* network error */
	COMEATAR_HTTP_ERROR,	/* HTTP error */
	COMETAR_AUTH_ERROR,		/* authentication error */
	COMETAR_PAR_ERROR,		/* parameters error */
	COMETAR_ERROR,			/* generic internal error */
} cometa_reply;
```

#### `cometa_init`
```
cometa_reply cometa_init(const char *device_id,  const char *server_name, const char * server_port, const char *platform);
```
Initialize the application to use Cometa and provides the necessary parameters
 to identify the Cometa server and the device.
 
| PARAMETER             | DESCRIPTION        | TYPE           |
|-----------------------|--------------------|----------------|
| `device_id`  	| device ID          | `const char *` | 
| `server_name`    	| Cometa server FQDN | `const char *` |
| `server_port`		| Cometa server port | `const char *` |
| `platform`		| device description | `const char *` |

@platform - a string (max 64 chars [a-zA-Z] only) 
@return - completion code

#### `cometa_attach`
```
struct cometa *cometa_attach(const char *app_id, int ssl, const char *cafile);
``` 

 Subscribe the device to the specified application. The application ID must match one application defined in the `/etc/cometa.conf` file. If SSL support is enabled then optionally the cafile can reference a PEM format file containing CA certificates to be used, or NULL if only the default Cometa CADIR path is to be searched.


| PARAMETER                   | DESCRIPTION         | TYPE    
|-----------------------------|---------------------|---
|  `app_id`  	| application ID      | `const char *` 
|  `ssl`  	| use SSL boolean     | `int`
|  `cafile`  	| client supplied CAfile      | `const char *`

 @return - the connection handle (pointer to opaque data structure) or NULL in case of error
 
 Upon successful completion the server returns to the device a  JSON object composed as follows: 
 ```
  {"msg": "200 OK", "heartbeat": 60, "time": 142334566 } 
 ```
Note: The server message is not directly accessible from the application.

####`cometa_send`
```
cometa_reply cometa_send(struct cometa *handle, const char *buf, const int size);

```
Send a message upstream to the Cometa server. 

| PARAMETER                   | DESCRIPTION               | TYPE    
|-------------------------------|-------------------------|---
|  `handle`  	| Cometa handle      | `const char *` 
|  `buf`  	| data buffer      | `const char *` 
|  `size`  	| data buffer size      | `const int` 
 If a Webhook is specified for the Application in the server `/etc/cometa.conf` file, the message is posted to the indicated Webhook.

#### `cometa_bind_cb`
```
cometa_reply cometa_bind_cb(struct cometa *handle, cometa_message_cb cb, void *cb_private);

```
Bind a callback to a Cometa connection to handle messages received from the server. 

| PARAMETER                   | DESCRIPTION             | TYPE    
|-----------------------------|-------------------------|---
|  `handle`  	| Cometa handle      | `const char *` 
|  `cb`  	| callback function      | `cometa_message_cb` 
|  `cb_private`	| private context pointer      | `void *`

```
 typedef char *(*cometa_message_cb)(const int data_size, void *data);
```

| PARAMETER                   | DESCRIPTION             | TYPE    
|-----------------------------|-------------------------|---
|  `data_size`  	| message data size      | `const int` 
|  `data`  	| message data      | `void *`

Callback to upon message reception. The message is released after control returns to the library at the end of the callback. If the user code needs to use the content after returning, it should be copied into another buffer in the callback.
 
If the callback returns a pointer to a NULL-terminated string, the string is sent back to Cometa and relayed to the application server. If there is no message to send back the callback returns NULL. The response message memory is not released by the library.

####`cometa_error`
````
cometa_reply cometa_error(struct cometa *handle);
````
Return the last reply error in a function for the connection.

| PARAMETER                   | DESCRIPTION             | TYPE
|-----------------------------|-------------------------|---
|  `handle`  	| Cometa handle      | `const char *` 
 
