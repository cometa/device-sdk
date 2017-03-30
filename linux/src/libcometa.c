/*
 * Cometa is a cloud infrastructure for embedded systems and connected 
 * devices developed by Visible Energy, Inc.
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
 */

/*
 * @file    libcometa.c
 *
 * @brief   Library main code to connect a linux device to the Cometa infrastructure.
 *
 */

#include <string.h>
#ifdef WITH_SSL
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <fnmatch.h>

#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h> 
#include <signal.h> 
#include <unistd.h>
#include <err.h>
#include <time.h>
#include <pthread.h>
#include <sys/queue.h>

#include <errno.h>
#include <strings.h>

#include "http_parser.h"
#include "libcometa.h"

/* time difference - replaces timersub() BSD only (<sys/time.h>)*/
# define timersubtract(a, b, result)						      \
  do {									      \
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;			      \
    (result)->tv_usec = (a)->tv_usec - (b)->tv_usec;			      \
    if ((result)->tv_usec < 0) {					      \
      --(result)->tv_sec;						      \
      (result)->tv_usec += 1000000;					      \
    }									      \
  } while (0)

/** Public structures and constants **/

/* special one byte chunk-data line from devices */
#define MSG_HEARTBEAT   0x06
/* special one byte chunk-data line from devices */
#define MSG_UPSTREAM    0x07

/* print debugging details on stderr - the DEBUG symbol is specified in the Makefile */
#ifdef DEBUG 
#define debug_print(...) \
            do { fprintf(stderr, ##__VA_ARGS__); } while (0)       
#else            
#define debug_print(...) \
            do {  } while (0)
#endif

#define S_ON_HEADER_INVOKED 1
#define S_ON_BODY_INVOKED 2
/*
 * The cometa structure contains the connection socket and buffers.
 *
 */
struct cometa {
    int sockfd;					    /* socket to Cometa server */
    char recvBuff[MESSAGE_LEN];		/* received buffer */
    char sendBuff[MESSAGE_LEN];		/* send buffer */
    int	app_sockfd;					/* socket to the application server */
    char *app_name;					/* application name */
    char *app_id;					/* application key */
    cometa_message_cb user_cb;		/* message callback */
    void *user_private;				/* private context pointer for message callback */
    pthread_t	tloop;				/* thread for the receive loop */
    pthread_t	tbeat;				/* thread for the heartbeat */
    pthread_rwlock_t hlock;     	/* lock for heartbeat */
    int	hz;							/* heartbeat period in sec */	
    cometa_reply reply;				/* last reply code */
    int flag;                       /* disconnection flag */

    int state;
    http_parser parser;

#ifdef WITH_SSL
    BIO     *bconn;
    SSL     *ssl;
    SSL_CTX *ctx;
#endif    
};

/** Library global variables **/

/* global variable holding this device's identity  */
struct {
	char *id;     	/* device id */
    char *server_name;  /* server FQDN */
    char *server_port;  /* server port */
	char *info;		/* device platform information */
} device;

/* last used connection */
struct cometa *conn_save = NULL;
static char *cafile_save = NULL;

/** Functions definitions **/

ssize_t cometa_write(struct cometa *c) {
#ifdef WITH_SSL
    if (c->bconn) {
        return SSL_write(c->ssl, c->sendBuff, strlen(c->sendBuff));
    } else
#endif
        return write(c->sockfd, c->sendBuff, strlen(c->sendBuff));
        //return send(c->sockfd, c->sendBuff, strlen(c->sendBuff), MSG_DONTWAIT);
    return -1;
}
ssize_t cometa_read(struct cometa *c, char *buffer, size_t n) {
#ifdef WITH_SSL
    if (c->bconn) {
        return SSL_read(c->ssl, buffer, n);
    } else
#endif
        return read(c->sockfd, buffer, n);
    return -1;
}
static int parse(struct cometa *c, http_parser_settings *s, int n)
{
    size_t skip = http_parser_execute(&c->parser, s, c->recvBuff, n);
    if (skip) {
        memmove(c->recvBuff, c->recvBuff + skip, skip);
    }
    return skip;
}
static int on_headers_complete(http_parser *p)
{
    struct cometa *c = p->data;
    debug_print("\n***HEADERS COMPLETE***\n\n");
    c->state |= S_ON_HEADER_INVOKED;
    return 0;
}
static int on_body(http_parser *p, const char* at, size_t length)
{
    struct cometa *c = p->data;
    debug_print("\n*** BODY ***\n\n");
    debug_print("Body: %.*s\n", (int)length, at);
    c->state |= S_ON_BODY_INVOKED;
    return 0;
}
static int on_body_user_cb(http_parser *p, const char* at, size_t length)
{
    struct cometa *c = p->data;

    debug_print("DEBUG: received from server\r\n:%.*s\n", (int)length, at);

    if (c->user_cb) {
        char *response = c->user_cb(length, (char *)at, c->user_private);
        sprintf(c->sendBuff, "%x\r\n%s\r\n", (int)strlen(response), response);
        debug_print("DEBUG: sending response:\r\n%s\n", c->sendBuff);
    } else {
        sprintf(c->sendBuff, "%x\r\n\r\n", 2);
        debug_print("DEBUG: sending empty response.\r\n");
    }
    cometa_write(c);

    return 0;
}

#ifdef WITH_SSL
static int 
verify_callback(int ok, X509_STORE_CTX *store)
{
    char data[256];
 
    if (!ok)
    {
        X509 *cert = X509_STORE_CTX_get_current_cert(store);
        int  depth = X509_STORE_CTX_get_error_depth(store);
        int  err = X509_STORE_CTX_get_error(store);
 
        fprintf(stderr, "-Error with certificate at depth: %i\n", depth);
        X509_NAME_oneline(X509_get_issuer_name(cert), data, 256);
        fprintf(stderr, "  issuer   = %s\n", data);
        X509_NAME_oneline(X509_get_subject_name(cert), data, 256);
        fprintf(stderr, "  subject  = %s\n", data);
        fprintf(stderr, "  err %i:%s\n", err, X509_verify_cert_error_string(err));
    }
 
    return ok;
}

static long 
post_connection_check(SSL *ssl, char *host)
{
    X509      *cert;
    X509_NAME *subj;
    char      data[256];
    int       extcount;
    int       ok = 0;
 
    /* Checking the return from SSL_get_peer_certificate here is not strictly
     * necessary.  With our example programs, it is not possible for it to return
     * NULL.  However, it is good form to check the return since it can return NULL
     * if the examples are modified to enable anonymous ciphers or for the server
     * to not require a client certificate.
     */
    if (!(cert = SSL_get_peer_certificate(ssl)) || !host)
        goto err_occured;
    if ((extcount = X509_get_ext_count(cert)) > 0)
    {
        int i;
 
        for (i = 0;  i < extcount;  i++)
        {
            char *extstr;
            X509_EXTENSION *ext;
 
            ext = X509_get_ext(cert, i);
            extstr = (char*) OBJ_nid2sn(OBJ_obj2nid(X509_EXTENSION_get_object(ext)));
 
            if (!strcmp(extstr, "subjectAltName"))
            {
                int j;
                const unsigned char 	*data;
                STACK_OF(CONF_VALUE) 	*val;
                CONF_VALUE 				*nval;
                const X509V3_EXT_METHOD *meth;
                void 					*ext_str = NULL;
 
                if (!(meth = X509V3_EXT_get(ext)))
                    break;
                data = ext->value->data;

#if (OPENSSL_VERSION_NUMBER > 0x00907000L)
                if (meth->it)
                  ext_str = ASN1_item_d2i(NULL, &data, ext->value->length,
                                          ASN1_ITEM_ptr(meth->it));
                else
                  ext_str = meth->d2i(NULL, &data, ext->value->length);
#else
                ext_str = meth->d2i(NULL, &data, ext->value->length);
#endif
                val = meth->i2v(meth, ext_str, NULL);
                for (j = 0;  j < sk_CONF_VALUE_num(val);  j++)
                {
                    nval = sk_CONF_VALUE_value(val, j);
                    if (!strcmp(nval->name, "DNS") &&
		        (!strcmp(nval->value, host) || fnmatch(nval->value, host, 0)))
                    {
                        ok = 1;
                        break;
                    }
                }
            }
            if (ok)
                break;
        }
    }
 
    if (!ok && (subj = X509_get_subject_name(cert)) &&
        X509_NAME_get_text_by_NID(subj, NID_commonName, data, 256) > 0)
    {
        data[255] = 0;
        if (strcasecmp(data, host) != 0)
            goto err_occured;
    }
 
    X509_free(cert);
    return SSL_get_verify_result(ssl);
 
err_occured:
    if (cert)
        X509_free(cert);
    return X509_V_ERR_APPLICATION_VERIFICATION;
}

#define CADIR "/etc/ssl/certs"

static SSL_CTX *
setup_client_ctx(const char *cafile)
{
    SSL_CTX *ctx;
 
    ctx = SSL_CTX_new(SSLv23_method());
    if (SSL_CTX_load_verify_locations(ctx, cafile, CADIR) != 1)
        fprintf(stderr, "ERROR: Error loading CA file and/or directory (verify_locations).\n");
    if (SSL_CTX_set_default_verify_paths(ctx) != 1)
        fprintf(stderr, "Error loading default CA file and/or directory (verify_path).\n");

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
    SSL_CTX_set_verify_depth(ctx, 4);
    return ctx;
}
#endif

/*
 * The heartbeat thread.
 *
 * This thread detects a server disconnection and attempts to reconnect to a server in the Cometa ensemble.
 *
 * The hearbeat is a chunk of length 3 with the MSG_HEARBEAT byte and closed with CRLF.
 *
 */
static void *
send_heartbeat(void *h) {
	struct cometa *handle, *ret_sub;
    int ret;
    ssize_t n;
    int ssl = 0;

	handle = (struct cometa *)h;
#ifdef WITH_SSL
    ssl = !!handle->ssl;
#endif

    do {
	    while (usleep(handle->hz * 1000000) == -1 && (errno == EINTR))
			/* interrupted by a SIGNAL */
			continue;
        //usleep(handle->hz * 1000000);

		if ((ret = pthread_rwlock_wrlock(&handle->hlock)) != 0) {
	        fprintf(stderr, "ERROR: in send_heartbeat. Failed to get wrlock. ret = %d. Exiting.\r\n", ret);
	        exit (-1);
	    }
		debug_print("DEBUG: sending heartbeat.\r\n");
		/* send a heartbeat */
        sprintf(handle->sendBuff, "1\r\n%c\r\n", MSG_HEARTBEAT); 

    	n = cometa_write(handle);
        /* check for connection state and reconnection flag */
        if (n <= 0 || handle->flag == 1) { //&& (errno == EPIPE)) {
            pthread_rwlock_unlock(&(handle->hlock));

            /* connection lost */
            debug_print("in send_heartbeat. Reconnecting: n = %d, errno = %d, flag = %d\n\r", (int)n, (int)errno, handle->flag);
            /* attempt to reconnect */
            /* TODO: add a random delay to avoid server flooding when many devices disconnect at the same time */
            ret_sub = cometa_attach(conn_save->app_id, ssl, cafile_save);
            if (ret_sub == NULL) {
                debug_print("ERROR: attempt to reconnect to the server failed.\n");
            }
            continue;
        }
		pthread_rwlock_unlock(&(handle->hlock));

	} while (1);
}	/* send_heartbeat */

/* 
 * The receive and dispatch loop thread.
 */
static void *
recv_loop(void *h) {
    http_parser_settings settings;

    int n = 0;
    struct cometa *handle = h;
    fd_set readset;

    memset(&settings, 0, sizeof(settings));
    settings.on_body = on_body_user_cb;

    while (1) {
        int result;
        do {
           FD_ZERO(&readset);
           FD_SET(handle->sockfd, &readset);
           result = select(handle->sockfd + 1, &readset, NULL, NULL, NULL);
        } while (result == -1 && errno == EINTR);

        pthread_rwlock_wrlock(&handle->hlock);
        n += cometa_read(handle, handle->recvBuff + n, MESSAGE_LEN - n - 1);
        n -= parse(handle, &settings, n);
        pthread_rwlock_unlock(&(handle->hlock));
    }
	return NULL;
}	/* recv_loop */


/*
 * Connect to the server.
 *
 * @result the connection socket or -1 -  not used with SSL.
 *
 */
static int 
en_connect(void) 
	{
    struct addrinfo hints;
	struct addrinfo *result; 
    int n;
    struct sockaddr_in *addr;
    char str[INET_ADDRSTRLEN];
    int sockfd;
	    
    /* DNS lookup for Cometa server */	
	memset(&hints, 0, sizeof hints);   // make sure the struct is empty
	hints.ai_family = AF_INET;         // don't care IPv4 or IPv6
	hints.ai_socktype = SOCK_STREAM;   // TCP stream sockets
	hints.ai_flags = AI_CANONNAME | AI_ADDRCONFIG;     // fill in IP list

	if ((n = getaddrinfo(device.server_name, device.server_port, &hints, &result)) != 0) {
		fprintf(stderr, "ERROR : getaddrinfo() could not get server name %s resolved (%s).\r\n", device.server_name, gai_strerror(n));
	    return -1;
	}

    addr = (struct sockaddr_in *)result->ai_addr;
    inet_ntop(AF_INET, &addr->sin_addr, str, sizeof str);
    
    /* open a socket with the selected server */
    if ((sockfd = socket(result->ai_family, result->ai_socktype, result->ai_protocol)) == -1) {
        fprintf(stderr, "ERROR: Could not open socket to server %s", str);
    }
    else {
        debug_print("Connecting to server %s\r\n", str);
    }
    /* connect to server */
    if (connect(sockfd, result->ai_addr, result->ai_addrlen) == -1) {
        fprintf(stderr, "ERROR: Could not connect to server %s\r\n", str);
        sockfd = -1;
    }   
    freeaddrinfo(result);

	/* return the socket */
    return sockfd;
}   /* en_connect */

/*
 * Initialize the application to use the library.  
 *
 * @param server_name - the Cometa server FQDN
 * @param server_port - the Cometa server port
 * @param device_id	- the id of the device to connect
 * @param platform - an (optional) platform description  
 *
 */
cometa_reply
cometa_init(const char *device_id, const char *server_name, const char * server_port, const char *platform)
{
    if (!server_name || !server_port)
        return COMETAR_PAR_ERROR;
	if (device_id && (strlen(device_id) <= DEVICE_ID_LEN))
		device.id = strdup(device_id);
	else
		return COMETAR_PAR_ERROR;

    device.server_name = (char *)server_name;
    device.server_port = (char *)server_port;
	if (platform) {
		device.info = strdup(platform);
    }
	else
		device.info = NULL;
        
#ifdef WITH_SSL
    if (!SSL_library_init()) {
        fprintf(stderr, "** OpenSSL initialization failed!\n");
        exit(-1);
    }
    SSL_load_error_strings();
    RAND_load_file("/dev/urandom", 1024);
#endif
    	
    /* ignore SIGPIPE and handle socket write errors inline  */
    signal(SIGPIPE, SIG_IGN);

	return COMEATAR_OK;
}	/* cometa_init */


/* 
 * Attach the initialized device to a Cometa registered application. 
 * 
 * @param app_id- the application ID
 * @param ssl- use https
 *
 * @info  Authentication is done using the app_id (one-way authentication).
 *
 * @return	- the connection handle
 *
 */
struct cometa *
cometa_attach(const char *app_id, int ssl, const char *cafile) {
    http_parser_settings settings;

    struct cometa *conn;
    char platform_buf[128];
    pthread_attr_t attr;
    int n;
#ifdef WITH_SSL
    long err;
#endif

#ifndef WITH_SSL
    if (ssl)
        return NULL;
#endif
	
    /* check when called for reconnecting */
    if (conn_save != NULL) {
        fprintf(stderr, "in cometa_attach: reconnecting\r\n");

        /* it is a reconnection */
        conn = conn_save;
        conn->flag = 0;
        /* cancel the receive loop thread */
//        pthread_cancel(conn->tloop);
        /* wait for the thread to complete */
//       pthread_join(conn->tloop, NULL);

        fprintf(stderr, "in cometa_attach: after join\r\n");
    } else {
        /* allocate data structure when called the first time */
        conn = calloc(1, sizeof(struct cometa));
        conn->flag = 0;
        /* save the global connection pointer for re-connecting */
        conn_save = conn;
        if (cafile) {
            if (cafile_save) {
                (void)free(cafile_save);
            }
            cafile_save = strdup(cafile);
        }
    
        /* save the parameters */
        if (app_id)
        	conn->app_id = strdup(app_id);
        else {
        	fprintf(stderr, "ERROR : Parameter error (app_id)\r\n");
        	conn->reply = COMETAR_PAR_ERROR;
            return NULL;		
        }

#ifdef WITH_SSL
        if (ssl)
            conn->ctx = setup_client_ctx(cafile);
#endif
    }
        
#ifdef WITH_SSL
    if (ssl) {
        conn->bconn = BIO_new_ssl_connect(conn->ctx);
        if (!conn->bconn) {
            fprintf(stderr, "Error creating connection BIO.\n");
            conn->reply = COMETAR_ERROR;
            return NULL;
        }
        BIO_get_ssl(conn->bconn, &conn->ssl);
        if (!conn->ssl) {
            return NULL;
        }
        SSL_set_mode(conn->ssl, SSL_MODE_AUTO_RETRY);

        if (BIO_set_nbio(conn->bconn, 0) != 1) {
            fprintf(stderr, "Unable to set BIO to blocking mode.\n");
            conn->reply = COMETAR_ERROR;
            return NULL;     
        }
        if (!BIO_set_conn_hostname(conn->bconn, device.server_name) ||
            !BIO_set_conn_port(conn->bconn, device.server_port)) {
            return NULL;
        }
        if (BIO_do_connect(conn->bconn) <= 0) {
            fprintf(stderr, "Error connecting to remote machine.\n");
            conn->reply = COMETAR_ERROR;
            return NULL;
        }
        if ((err = post_connection_check(conn->ssl, device.server_name)) != X509_V_OK) {
            fprintf(stderr, "-Error: peer certificate: %s\n", X509_verify_cert_error_string(err));
            fprintf(stderr, "Error checking SSL object after connection.\n");
            conn->reply = COMETAR_ERROR;
            return NULL;
        }

        fprintf(stderr, "DEBUG: SSL Connection opened\n");

        conn->sockfd = SSL_get_fd(conn->ssl);
    } else
#endif
    {
        /* select and connect to a server from the ensemble */
        conn->sockfd = en_connect();
        if (conn->sockfd == -1) {               /* No address succeeded */
            fprintf(stderr, "ERROR : Connection to server %s failed. Is the Cometa server running?\r\n", device.server_name);
            conn->reply = COMETAR_ERROR;
            return NULL;
        }
    }

    /*
     * ----------------------  send idevice attach request to cometa
     *   POST /v1/applications/{app_id}/devices/{device_id}
     *   {platform}
     *
     */
    sprintf(platform_buf, "%s", device.info);
    sprintf(conn->sendBuff, "POST /v1/applications/%s/devices/%s HTTP/1.1\r\nHost: api.cometa.io\r\nContent-Length: %zd\r\n\r\n%s", app_id, device.id, strlen(platform_buf), platform_buf);
    debug_print("DEBUG: sending URL:\r\n%s", conn->sendBuff);

    n = cometa_write(conn);
    if (n <= 0)  {
        fprintf(stderr, "ERROR: writing to cometa server socket.\r\n");
		conn->reply = COMEATAR_NET_ERROR;
        return NULL;
    }

    memset(&settings, 0, sizeof(settings));
    settings.on_headers_complete = on_headers_complete;
    settings.on_body = on_body;
    http_parser_init(&conn->parser, HTTP_RESPONSE);
    conn->parser.data = conn;

    n = 0;
    do {
        n += cometa_read(conn, conn->recvBuff + n, MESSAGE_LEN - n - 1);
        n -= parse(conn, &settings, n);
    } while (!(conn->state & S_ON_HEADER_INVOKED));

    n = 0;
    while (!(conn->state & S_ON_BODY_INVOKED)) {
        n += cometa_read(conn, conn->recvBuff + n, MESSAGE_LEN - n - 1);
        n -= parse(conn, &settings, n);
    }
    conn->state = 0;

    conn->recvBuff[n] = '\0';
    debug_print("DEBUG: received (%zd):\r\n%s\n", strlen(conn->recvBuff), conn->recvBuff);

    /* 
	 * A JSON object is returned by the Cometa server:
	 * 	 success:{ "msg": "200 OK", "heartbeat": 60, "time": 142334566 } 
	 * 	 failed: { "msg": "403 Forbidden" }
	 */
	if (conn->parser.status_code != 200) {
		conn->reply = COMETAR_AUTH_ERROR;
		return NULL;
	} 

	/* TODO: extract heartbeat from response */
	conn->hz = 60;	/* default to 1 min */
	
    /* device authentication handshake complete */
    /* ----------------------------------------------------------------------------------------------- */
	
    debug_print("DEBUG: device attach complete.\r\n");
    
    /* initialize and set thread detached attribute */ 
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    /* 
	 * start the receive and heartbeat threads if it is not a reconnection
	 */    
    if ((conn->tloop == 0) && (conn->tbeat == 0))  {
    	pthread_rwlock_init(&(conn->hlock),NULL);
    	/* start the receive loop */
    	if (pthread_create(&conn->tloop, &attr, recv_loop, (void *)conn)) {
    		fprintf(stderr, "ERROR: Failed to create main loop thread. Exiting.\r\n");
    		exit(-1);
    	}
       
    	/* start the heartbeat loop */
    	if (pthread_create(&conn->tbeat, &attr, send_heartbeat, (void *)conn)) {
    		fprintf(stderr, "ERROR: Failed to create heartbeat thread. Exiting.\r\n");
    		exit(-1);
    	}
    } else {
        /* start a new receive loop thread: needed because it is now a new server and a new socket */
        if (pthread_create(&conn->tloop, &attr, recv_loop, (void *)conn)) {
    		fprintf(stderr, "ERROR: Failed to create main loop thread. Exiting.\r\n");
    		exit(-1);
    	} else
            debug_print("DEBUG: Restarted receive loop.\r");
    }
    pthread_attr_destroy(&attr);

	conn->reply = COMEATAR_OK;
	return conn;
}	/* cometa_subscribe */

/*
 * Send a message upstream to the Cometa server. 
 * 
 * If a Webhook is specified for the Application, the message is relayed by Cometa to the server as specified in the webhook of the app in the registry.
 * If the Application has a storage bucket specified, the message is stored in the data bucket.
 *
 * (MESSAGE_LEN - 12) is the maximum message size.
 *
 */
cometa_reply cometa_send(struct cometa *handle, const char *buf, const int size) {
    int ret;
    ssize_t n;
    
    /* return if the reconnecting flag is set */
    if (handle->flag == 1)
        return COMEATAR_NET_ERROR;
        
    if ((ret = pthread_rwlock_wrlock(&handle->hlock)) != 0) {
        fprintf(stderr, "ERROR: in cometa_send. Failed to get wrlock. ret = %d. Exiting.\r\n", ret);
        exit (-1);
    }

    if (MESSAGE_LEN - 12 < size) {
        /* message too large */
        return COMETAR_PAR_ERROR;
    }
	debug_print("DEBUG: sending message upstream.\r\n");
	
	/* The device uses the MSG_UPSTREAM message marker in the first character to indicate  */
    /* an upstream message that is not a response to a publish request. */
    
    /* build the message with the data-chunk length in hex*/
    // sprintf(handle->sendBuff, "%x\r\n%c%.*s\r\n", size + 3, MSG_UPSTREAM, size, buf);
    sprintf(handle->sendBuff, "%x\r\n%c%.*s\r\n", size + 1, MSG_UPSTREAM, size, buf);   // MEG CRLF

    /* perform a single write for the data chunk */
    n = cometa_write(handle);
    
    pthread_rwlock_unlock(&(handle->hlock));

    /* check for SIGPIPE broken pipe */
    if ((n < 0) && (errno == EPIPE)) {
        /* connection lost */
        debug_print("in cometa_send: n = %d, errno = %d\n", (int)n, (int)errno);
        /* do nothing and let the heartbeat thread to try to reconnect */
        return COMEATAR_NET_ERROR;
    }
    if (n <= 0) {
        /* connection lost */
        debug_print("in cometa_send: n = %d, errno = %d\n", (int)n, (int)errno);
        /* do nothing and let the heartbeat thread to try to reconnect */
        return COMEATAR_NET_ERROR;    
    }

	return COMEATAR_OK;
}   /* cometa_send */

/*
 * Bind the @cb callback to the receive loop.
 *
 */
cometa_reply 
cometa_bind_cb(struct cometa *handle, cometa_message_cb cb, void *cb_private) {
	int ret;

	if ((ret = pthread_rwlock_wrlock(&handle->hlock)) != 0) {
            fprintf(stderr,"ERROR: in %s. Failed to get wrlock. ret = %d. Exiting.\r\n",__func__,ret);
            exit (-1); /* TODO: clean up API to avoid just bailing out */
        }

	handle->user_cb = cb;
	handle->user_private = cb_private;

        (void)pthread_rwlock_unlock(&(handle->hlock));

	return COMEATAR_OK;
}

/*
 * Getter method for the error code.
 */
cometa_reply
cometa_error(struct cometa *handle) {
	return handle->reply;
}
