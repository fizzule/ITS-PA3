/*
Programm zum abfangen von dem Passwort eines Benutzers bei MQTT Nachrichten an einem bestimmten Port.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <signal.h>
#include <arpa/inet.h>
#include <gpgme.h>

int sock_raw;
char *buffer;
char command[2000];
char user[256];
char pass[256];

/*
Schliesse Socket, wenn offen und gebe Buffer frei, wenn noch nicht geschehen.
*/
void close_all(){
	if (sock_raw >= 0){
		close(sock_raw);
		sock_raw = -1;
	}
	if (buffer != NULL) {
		free(buffer);
		buffer = NULL;
	}
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
	ssize_t data_size;
	struct sockaddr saddr;

	/* Usage */
	printf("You can enter Port first and User second after the command!\n");
	printf("If one or both are missing, the default values are used.\n");
	printf("Default-Port: 1883\n");
	printf("Default User: remote-control\n");
	
	/* Verarbeiten von spezifischen Eingaben */
	if(argc == 3){
		sniffport = (unsigned short) atoi(argv[1]);
		strcpy(user, argv[2]);
	} else {	
		sniffport = 1883;
		strcpy(user, "remote-control");
	}	

	/* Erstellen des Abbruch-Handlers */
	sigIntHandler.sa_handler = abbruch_handler;
	sigemptyset(&sigIntHandler.sa_mask);
	sigIntHandler.sa_flags = 0;

	sigaction(SIGINT, &sigIntHandler, NULL);
	
	printf("Finish!\n");
	return 0;
}
