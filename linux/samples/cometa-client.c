/*
 * Cometa is a cloud infrastructure for IoT and connected devices
 * developed by Visible Energy, Inc. (www.cometa.io).
 *
 * Copyright (C) 2013, 2015, 2017 Visible Energy, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

/*
 *
 * @file    cometa-client.c
 *
 * @brief   Stand-alone cometa client sample application. 
 *			The application executes a shell command received in a Cometa message and returns the command's output in the response.
 *
 *			Note: the application sends a timestamp to the server every 60 seconds as a way to demonstrate use of upstream events.
 *
 * @usage	cometa-client -s [server_name] [ -e ] -p [server_port] -a [app_id] {-d device_id} {-v}
 *				-s 	: Cometa server name (FQDN)
 *				-e 	: use ssl
 *				-p 	: Cometa server port
 *				-a 	: Cometa application ID to attach the device to (as defined in the Cometa server /etc/cometa.conf)
 * 				-d 	: the device ID. If not specified, the machine's MAC address is used as device_id
 *				-v for verbose (default is silent)
 *
 * @example ./cometa-client -s api.service.com -p 80 -k 946604ed1d981eca2879
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <ctype.h>
#include <signal.h>
#include <pthread.h>

#include <sys/ioctl.h>
#include <sys/types.h>    
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "libcometa.h"

/*
 * Cometa parameters. 
 * The application_id must match in the Cometa server parameters defined in /etc/cometa.conf
 * 
 */
 
char *cometa_server_name = NULL;
char *cometa_server_port = NULL;
char *cometa_application_id = NULL;
int cometa_use_ssl = 0;

/* The device ID */
char *device_id = NULL;

/* Obtain the device_id from the MAC address */
static char * get_device_id(void);

/* verbose flag */
int verbose = 0;

/*
 * The PLATFORM literal is added as a parameter when attaching to the Cometa server and returned in the device INFO command.
*/
#define PLATFORM 	"Linux-device"

/* Receive buffer globals */
char rcvBuf[MESSAGE_LEN];


/*
 * Process a request received from the Cometa server containing a shell command.
 * @return - > 0 in case of success.
 */
int
processCmd(const char *cmd, char *cmd_output) 
{
	FILE *fp;
  	char line[1024];

	cmd_output[0] = '\0';
	
  	/* Open the command output as a pipe */
  	fp = popen(cmd, "r");
  	if (fp == NULL) {
    	strcpy(cmd_output ,"Failed to run command\n" );
    	return -1;
  	}

  	/* Read the output a line at a time - output it. */
  	while (fgets(line, sizeof(line), fp) != NULL) {
  		if ((strlen(cmd_output) + strlen(line)) < MESSAGE_LEN - 1)
	    	strcat(cmd_output, line);
	    else
	    	return -1;
  	}

  	/* close the pipe */
  	pclose(fp);

	return 1;
}

/*
 * Callback for messages (requests) received from the application (via cometa).
 *
 * @data_len - length message buffer 
 * @data - message buffer 
 * 
 * The buffer is reused by the cometa client library. Copy the buffer if needed after returning.
 *
 */
char cmdOutput[MESSAGE_LEN];
static char *
message_handler(const int data_len, void *data, void *priv)
{
	time_t now;
    struct tm  ts;
    char dateBuf[80];
    char cmd[512];
	
	/* save the buffer */
	memcpy(rcvBuf, data, data_len);
	
	/* time */
	time(&now);
	/* Format time, "ddd yyyy-mm-dd hh:mm:ss zzz" */
	ts = *localtime(&now);
	strftime(dateBuf, sizeof(dateBuf), "%Y-%m-%d %H:%M:%S", &ts);

	/* zero-terminate the buffer for printing */
	rcvBuf[data_len] = '\0';
	if (verbose)
		fprintf(stderr, "%s: In message_handler.\r\nReceived %d bytes:\r\n%s", dateBuf, data_len, (char *)rcvBuf);
	
	/*
	 * Here is where the received message is interpreted and proper action taken.
	 */
	/* remove CRLF at the end of the Chunked-encoded message */
	rcvBuf[data_len] = '\0';
    cmdOutput[0] = '\0';
    sprintf(cmd, "\"%s\"", rcvBuf);
    if (data_len > 0)
        processCmd(cmd, cmdOutput);

	
	/* 
	 * Return the output as response.
	 */
	return cmdOutput;
}

/*
 *
 * Function called by the main loop to send a timestamp event upstream.
 *
 * To show usage of the cometa_send() function to send events data upstream.
 *
 */
static void
send_time_upstream(struct cometa *handle) 
{
    time_t now;
    struct tm  ts;
    char dateBuf[80];
    char sendBuf[4096];
    cometa_reply ret;
    
    /* Get current time */
	time(&now);
	
	/* Format time, "ddd yyyy-mm-dd hh:mm:ss zzz" */
	ts = *localtime(&now);
	strftime(dateBuf, sizeof(dateBuf), "%Y-%m-%d %H:%M:%S", &ts);
	sprintf(sendBuf, "{\"id\":\"%s\",\"time\":\"%s\"}", device_id, dateBuf);
	
	if (verbose)
	    fprintf(stderr, "Sending %s (len = %zd)\n", sendBuf, strlen(sendBuf));
    ret = cometa_send(handle, sendBuf, strlen(sendBuf));
    if (ret != COMEATAR_OK) {
 		fprintf(stderr, "DEBUG: In send_time_upstream. Error in cometa_send() returned %d\n", ret);
    }
}

/*
 * Use the eth0 MAC address as device_id.
 *
 */
char DeviceId[DEVICE_ID_LEN];
static char *
get_device_id(void) {
	int s;
    struct ifreq buffer;

    s = socket(PF_INET, SOCK_DGRAM, 0);
    memset(&buffer, 0x00, sizeof(buffer));
    strcpy(buffer.ifr_name, "eth0");
    ioctl(s, SIOCGIFHWADDR, &buffer);
    close(s);
    
    sprintf(DeviceId, "%.2X%.2X%.2X%.2X%.2X%.2X", (unsigned char)buffer.ifr_hwaddr.sa_data[0], (unsigned char)buffer.ifr_hwaddr.sa_data[1], (unsigned char)buffer.ifr_hwaddr.sa_data[2], (unsigned char)buffer.ifr_hwaddr.sa_data[3], (unsigned char)buffer.ifr_hwaddr.sa_data[4], (unsigned char)buffer.ifr_hwaddr.sa_data[5]);
	return DeviceId;
}

/*
 * Application entry point.
 * 
 * Command line parameters:
 *		-s 	: Cometa server name (FQDN)
 *		-p 	: Cometa server port
 *		-e 	: use ssl
 *		-a 	: Cometa application ID to attach the device to (as defined in the Cometa server /etc/cometa.conf)
 * 		-d 	: the device ID. If not specified, the machine's MAC address is used as device_id
 *		-v for verbose (default is silent)
 *
 */
int 
main(int argc, char **argv) 
{
	struct cometa *cometa;
	cometa_reply ret;
	int c;
	
    while ((c = getopt (argc, argv, "s:p:ea:d:v?")) != -1)
        switch (c) {
            case 's':
                cometa_server_name = strdup(optarg);
                break; 
            case 'p':
                cometa_server_port = strdup(optarg);
                break;    
            case 'e':
                cometa_use_ssl = 1;
                break;    
            case 'a':
                cometa_application_id = strdup(optarg);
                break;
            case 'd':
                device_id = strdup(optarg);
                break;
            case 'v':
                verbose = 1;
                break;
            case '?':
                if (optopt == 's' || optopt == 'p' || optopt == 'a' || optopt == 'd')
                    fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                else if (isprint(optopt) && (optopt != 'v'))
                    fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                else
                    fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
                return 1;
            default:
                abort ();
       }
        
    if (cometa_server_name == NULL || cometa_server_port == NULL  || cometa_application_id == NULL) {
        fprintf(stderr, "Usage: cometa-client -s [server_name] -p [server_port] [ -e ] -a [app_id] {-d device_id} {-v}\r\n");
		return 1;
	}

	/* use the machine's MAC address as device_id if not in the command line */
	if (device_id == NULL)
		device_id = get_device_id();    

	fprintf(stderr, "%s started.\r\n", argv[0]);
	fprintf(stderr, "Connecting to Cometa server: %s:%s\r\n", cometa_server_name, cometa_server_port);

	/* 
     * Initialize this device to use the cometa library.
     *
     * Note: the Cometa library sets to ignore SIGPIPE signals (broken pipe).
     *
     */
	ret = cometa_init(device_id, cometa_server_name, cometa_server_port, PLATFORM);
	if (ret != COMEATAR_OK) {
		fprintf(stderr, "DEBUG: Error in cometa_init: %d. Exiting.\r\n", ret);
		exit(-1);
	}
    
    /* 
     * Ignore exit status of child processes and avoid zombie processes. 
     *
     */
    signal(SIGCHLD, SIG_IGN);
	
    /* 
     * Attach to cometa. 
     */	
    cometa = cometa_attach(cometa_application_id, cometa_use_ssl, NULL);
	if (cometa == NULL) {
		fprintf(stderr, "DEBUG: Error in cometa_attach. Exiting.\r\n");
		exit(-1);
	}
	
	/* 
     * Bind the callback for messages received from the application server (via Cometa).
     */
	ret = cometa_bind_cb(cometa, message_handler, NULL);
	if (ret != COMEATAR_OK) {
		fprintf(stderr, "DEBUG: Error in cometa_bind_cb: %d. Exiting.\r\n", ret);
		exit(-1);
	}
	fprintf(stderr, "%s: connection completed for device ID: %s\r\n", argv[0], device_id);
    
	/* 
     * The main() thread is done, this device is subscribed to cometa and is ready to receive
	 * messages handled by the callback. Normally here is where this application's main loop would start.
     * Otherwise, we need to call pthread_exit() explicitly to allow the working threads in
	 * the cometa library to continue and for the callback to be executed even after main completes.
     *
	 */
#ifdef NODEF
	pthread_exit(NULL);
#endif
     
	/*
	 * Main loop
	 */
	do {
		sleep(60);
        /* send a simple message upstream */
        send_time_upstream(cometa);
	} while(1);   
}   /* main */
