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
#include <errno.h>

#define BUF_SIZE 65536

int sock;
char buffer[BUF_SIZE+1];
char abbruch = 0;

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
	abbruch = 1;
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

	int value;
	int n;
	char ch;
	
	gpgme_ctx_t ctx;
    	gpgme_error_t err;
    	gpgme_data_t in, out;
    	gpgme_verify_result_t verify_result;
	int ret;
	

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
	
	n = sscanf(argv[1], "%d%c", &value, &ch);
        /* Wenn sscanf keine Nummer konvertieren kann */
    	if (n != 1) {
		printf("Please provide correct port number!\n");
		usage();
		return 1;
	}
	
	/* Begin setup of GPGME */
	setlocale (LC_ALL, "");
    	gpgme_check_version (NULL);
    	gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
    	/* End setup of GPGME */

    	err = gpgme_engine_check_version (GPGME_PROTOCOL_OpenPGP);
    	if(err){
		printf("Error at engine check!\n");
		return 1;
	}
    
    	// Create the GPGME Context
    	err = gpgme_new (&ctx);
    	if(err){
		printf("Error at context creation!\n");
		return 1;
	}
	
    	// Set the context to textmode
    	gpgme_set_textmode (ctx, 1);
    	// Enable ASCII armor on the context
    	gpgme_set_armor (ctx, 1);	
			
	/* Erstelle Server Port */
    	memset((char *) &serveraddr, 0, sizeof(serveraddr));
     
    	serveraddr.sin_family = AF_INET;
    	serveraddr.sin_port = htons(atoi(argv[1]));
    	serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
     
	
     	/* Oeffnen des Socket */
	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(sock < 0){
		printf("Socket Error\n");
		return 1;
	}
     
    	/* Binde Socket */
	bindret = bind(sock , (struct sockaddr*)&serveraddr, sizeof(serveraddr));
	if(bindret < 0){
        	close(sock);
		return 1;
    	}
     
	saddr_size = sizeof saddr;
	
    	/* Entgegennehmen der Pakete */
    	while(!abbruch)
    	{      
		data_size = recvfrom(sock, buffer, BUF_SIZE, 0, &saddr, &saddr_size);
		if(data_size < 0){
        		abbruch = 1;
			break;
    		}
		
		/* printf("Data: %s\n" , buffer); */
 
		err = gpgme_data_new_from_mem (&in, buffer, data_size, 0);
         	if(err){
			printf("Error at data creation for input!\n");
			abbruch = 1;
			break;
		}
		
		// Create a data object pointing to the out buffer
    		err = gpgme_data_new (&out);
    		if(err){
			printf("Error at data creation for output!\n");
			gpgme_data_release (in);
			abbruch = 1;
			break;
		}

    		// Perform a decrypt/verify action
    		err = gpgme_op_verify (ctx, in, 0, out);

    		// Retrieve the verification result
    		verify_result = gpgme_op_verify_result (ctx);

    		// Error handling
    		if (err != GPG_ERR_NO_ERROR && !verify_result){
			printf("The verify failed!\n");	
			gpgme_data_release (in);
			gpgme_data_release (out);
			break;
		}

    		// Check if the verify_result object has signatures
    		if (verify_result && verify_result->signatures && gpg_err_code(verify_result->signatures->status) == GPG_ERR_NO_ERROR) {
			
			// Rewind the "out" data object
    			ret = gpgme_data_seek (out, 0, SEEK_SET);
    			// Error handling
    			if (ret){
        			if (gpgme_err_code_from_errno (errno)){
					printf("Error at rewinding data!\n");
					gpgme_data_release (in);
					gpgme_data_release (out);
					break;
				}
			}
    			// Read the contents of "out" and place it into buf
    			ret = gpgme_data_read (out, buffer, BUF_SIZE);
        		if (ret){
        			if (gpgme_err_code_from_errno (errno)){
					printf("Error at reading data!\n");
					gpgme_data_release (in);
					gpgme_data_release (out);
					break;
				}
			}
			printf("Correct Signature!\n");
			printf("%.*s\n", ret, buffer);
		}else{
			printf("Incorrect Signature!\n");
		}
	
		gpgme_data_release (in);
		gpgme_data_release (out);
    	}
	
	close(sock);
    	// Release the context
	gpgme_release (ctx);
	printf("Finished!\n");
	return abbruch;
}
