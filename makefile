CC = gcc
CFLAGS = -g -Wall 
LINKER = #-lcrypto

TARGETSERVER = pa3_server
TARGETCLIENT = pa3_client

default: all

all: server client

server: $(TARGETSERVER)
	$(CC) $(CFLAGS) -o $(TARGETSERVER) $(TARGETSERVER).c $(LINKER)

client: $(TARGETCLIENT)
	$(CC) $(CFLAGS) -o $(TARGETCLIENT) $(TARGETCLIENT).c $(LINKER)

clean:
	$(RM) $(TARGETSERVER)
	$(RM) $(TARGETCLIENT)
