CC = gcc
CFLAGS = -g -Wall 
LINKER = $(shell gpgme-config --libs --cflags)

TARGETSERVER = pa3_server
TARGETCLIENT = pa3_client

default: all

all: server client

server: $(TARGETSERVER)
	$(CC) $(CFLAGS) -o $(TARGETSERVER) $(LINKER) $(TARGETSERVER).c 

client: $(TARGETCLIENT)
	$(CC) $(CFLAGS) -o $(TARGETCLIENT) $(LINKER) $(TARGETCLIENT).c

clean:
	$(RM) $(TARGETSERVER)
	$(RM) $(TARGETCLIENT)
