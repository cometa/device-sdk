/*
 * Cometa is a cloud infrastructure for embedded systems and connected 
 * devices developed by Visible Energy, Inc.
 *
 * Copyright (C) 2013, 2015 Visible Energy, Inc.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* @file libcometa.h
 *
 * Cometa client library include file for vanilla linux systems.
 *
 */

/** Public structures and constants **/

/* Cometa server FQ names and port */
 
#define DEVICE_ID_LEN   32
#define DEVICE_KEY_LEN   32
#define DEVICE_INFO_LEN 64
#define APP_NAME_LEN 32
#define APP_KEY_LEN 32
#define MESSAGE_LEN 32768

/* 
 * The opaque data structure cometa holds the context for the library
 * persistent HTTP connection and the device credentials.
 *
 * the reply attribute contains the reply response code for the last operation
 */
struct cometa;

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

/** Cometa API functions **/

/*
 * All the function of this library are synchronous, that is they block until
 * the requested operation is completed or an error or timeout occurred.
 *
 */

/*
 * Initialize the application to use Cometa and provides the necessary parameters
 * to identify the Cometa server and the device. 
 * The Cometa server name and port to connect to are in @server_name and @server_port. The device ID is in @device_id.
 * The optional parameter @platform is a string (max 64 chars [a-zA-Z] only) describing the device
 * platform and used only as information for device management and analytics.
 *
 * @return - the library connection handle
 *
 */

cometa_reply cometa_init(const char *device_id,  const char *server_name, const char * server_port, const char *platform);

/* 
 * Attach the device to the application @app_name at the application server. 
 *
 * @return - the connection handle or NULL in case of error
 *
 */
 
struct cometa *cometa_attach(const char *app_id);

/*
 * Send a message upstream to the Cometa server. 
 * 
 * If a Webhook is specified for the Application, the message is relayed by Cometa to the server as specified in the webhook of the app in the registry.
 * If the Application has a storage bucket specified, the message is stored in the data bucket.
 *
 * (MESSAGE_LEN - 12) is the maximum message size.
 *
 */
cometa_reply cometa_send(struct cometa *handle, const char *buf, const int size);
	
/* 
 * Callback to user code upon message reception. The message is released after control
 * returns to the library at the end of the callback. If the user code needs to use the 
 * content after returning, it should be copied into another buffer in the callback.
 *
 * If the callback returns a pointer to a NULL-terminated string, the string is sent back
 * to Cometa and relayed to the application server. If there is no message to send back
 * the callback returns NULL. The response message memory is not released by the library.
 *
 * @param	data_size - size of the message
 * @param	data - message
 *
 * @return - the response message to be sent to the application server
 */
typedef char *(*cometa_message_cb)(const int data_size, void *data);

/*
 * Bind the @cb callback to a message received event from the connection with the specified @handle.
 * The message received by the callback is zero-terminated.
 *
 */

cometa_reply cometa_bind_cb(struct cometa *handle, cometa_message_cb cb);

/*
 * Return the last reply error in a function for the connection in @handle.
 */
cometa_reply cometa_error(struct cometa *handle);
