CC=gcc
# to use SSL define USE_SSL 
# the server root certificate is expected in the file rootcert.pem in the same directory
CUSTOM_CFLAGS=-I./src -Wall -ggdb3 -O3 -DWITH_SSL -DDEBUG
LIBS=-lpthread -lcrypto -lssl -lm
CFLAGS=$(CUSTOM_CFLAGS) $(SYS_CFLAGS)

all: cometa-client

cometa-client: ./samples/cometa-client.o  ./src/libcometa.o ./src/http_parser.o
	$(CC) -o ./samples/$@ $(CFLAGS) $^ $(LIBS)

clean:
	rm -f ./src/*.o ./samples/*.o ./samples/cometa-client
