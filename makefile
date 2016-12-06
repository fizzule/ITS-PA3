default: all

all: pa3_server pa3_client

pa3_client: pa3_client
	gcc -g -Wall -o pa3_client pa3_client.c -lgpgme
	
pa3_server: pa3_server
	gcc -g -Wall -o pa3_server pa3_server.c -lgpgme

clean:
	$(RM) pa3_server
	$(RM) pa3_client
