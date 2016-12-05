/*
Server für das Empfangen von PGP verschlüsselten Nachrichten.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <locale.h>
#include <gpgme.h>

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
	printf("./pa3_server SERVER_PORT\n");
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
	
	int bindret;
	
	socklen_t saddr_size;
	ssize_t data_size;
	struct sockaddr saddr;	
	struct sockaddr_in serveraddr;

	/* Erstellen des Abbruch-Handlers */
	sigIntHandler.sa_handler = abbruch_handler;
	sigemptyset(&sigIntHandler.sa_mask);
	sigIntHandler.sa_flags = 0;

	sigaction(SIGINT, &sigIntHandler, NULL);
	
	/* Verarbeiten von spezifischen Eingaben */
	if(argc == 2){
		printf("Port: %s\n", argv[1]);
	} else {	
		printf("Please provide a correct port number!\n");
		usage();
		return 1;
	}
	
     	/* Oeffnen des Socket */
	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(sock < 0){
		printf("Socket Error\n");
		return 1;
	}
     
    	/* Erstelle Server Port */
    	memset((char *) &serveraddr, 0, sizeof(serveraddr));
     
    	serveraddr.sin_family = AF_INET;
    	serveraddr.sin_port = htons(atoi(argv[1]));
    	serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
     
    	/* Binde Socket */
	bindret = bind(sock , (struct sockaddr*)&serveraddr, sizeof(serveraddr));
	if(bindret < 0){
        	close_all();
		return 1;
    	}
     
	saddr_size = sizeof saddr;
	
    	/* Entgegennehmen der Pakete */
    	while(1)
    	{      
		data_size = recvfrom(sock, buffer, 65536, 0, &saddr, &saddr_size);
		if(data_size < 0){
        		close_all();
			return 1;
    		}
 
         	
       		//print details of the client/peer and the data received
        	//printf("Received packet from %s:%d\n", inet_ntoa(saddr.sin_addr), ntohs(si_other.sin_port));
        	printf("Data: %s\n" , buffer);
    	}
	
	close_all();
	printf("Finished!\n");
	return 0;
}
