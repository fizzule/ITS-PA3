CC = gcc
CFLAGS = -g -Wall 
LINKER = -lgpgme

TARGETSERVER = pa3_server
TARGETCLIENT = pa3_client

default: all

all: server client

server: pa3_server
	$(CC) $(CFLAGS) -o pa3_server pa3_server.c $(LINKER)

client: $(TARGETCLIENT)
	$(CC) $(CFLAGS) -o pa3_client pa3_client.c $(LINKER)

clean:
	$(RM) pa3_server
	$(RM) pa3_client
