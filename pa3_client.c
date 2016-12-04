/*
Client für das Senden von PGP verschlüsselten Nachrichten.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
//#include <gpgme.h>

int sock;
char buffer[65536];

/*
Schliesse Socket, wenn offen und gebe Buffer frei, wenn noch nicht geschehen.
*/
void close_all(){
	if (sock >= 0){
		close(sock);
		sock = -1;
	}
	//if (buffer != NULL) {
	//	free(buffer);
	//	buffer = NULL;
	//}
}

/*
Gebe Usage aus.
*/
void usage(){
	printf("Please add all parameters as shown below through the console. \n");
	printf("./pa3_client SERVER_ADRESS SERVER_PORT USERNAME \"Message to encypt\" \n");
}

/*
Spezieller Handler bei Abbruch mit Strg+C um das Programm korrekt zu schliessen.
s: Signal ID
*/
void abbruch_handler(int s){
	close_all();
	exit(1);
}

/*
Hauptmethode erstellt Abbruch-Handler, startet Sniffer und sendet am Ende die "beamer_off"-Nachricht
moegliche commands:
./sniffer --> benutzt Default-Werte für Port und User
./sniffer <port> <user> --> spezifische Eingabe von Port und User
*/
int main(int argc, char **argv){

	struct sigaction sigIntHandler;
	
	socklen_t saddr_size;
	struct sockaddr_in saddr;	

	saddr_size = sizeof(saddr);
	
	/* Erstellen des Abbruch-Handlers */
	sigIntHandler.sa_handler = abbruch_handler;
	sigemptyset(&sigIntHandler.sa_mask);
	sigIntHandler.sa_flags = 0;

	sigaction(SIGINT, &sigIntHandler, NULL);
	
	/* Verarbeiten von spezifischen Eingaben */
	if(argc == 5){
		printf("Address: %s\n", argv[1]);
		printf("Port: %s\n", argv[2]);
		printf("Username: %s\n", argv[3]);
		printf("Message: %s\n", argv[4]);
	} else {	
		printf("Please provide correct parameters!\n");
		usage();
		return 1;
	}
 
	/* Oeffnen des Socket */
	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(sock < 0){
		printf("Socket Error\n");
		return 1;
	}
 
    	memset((char *) &saddr, 0, sizeof(saddr));
    	saddr.sin_family = AF_INET;
    	saddr.sin_port = htons(atoi(argv[2]));
     
    	if (inet_aton(argv[1] , &saddr.sin_addr) == 0){
        	fprintf(stderr, "inet_aton() failed\n");
		close_all();
        	return 1;
    	}
 
    	while(1)
    	{ 
        	//send the message
        	if (sendto(sock, argv[4], strlen(argv[4]) , 0 , (struct sockaddr *) &saddr, saddr_size)==-1){
            		close_all();
        		return 1;
        	}
    	}
 
	close_all();
	printf("Finished!\n");
	return 0;
}
