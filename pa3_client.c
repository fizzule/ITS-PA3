/*
Client fuer das Senden von PGP verschluesselten Nachrichten.
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

/*
Gebe Usage aus.
*/
void usage(){
	printf("Please add all parameters as shown below through the console. \n");
	printf("./pa3_client SERVER_ADRESS SERVER_PORT USERNAME \"Message to encypt\" \n");
}

/*
Hauptmethode erstellt gpg Kontext und sendet am Ende die PGP-Nachricht
*/
int main(int argc, char **argv){
	
	socklen_t saddr_size;
	struct sockaddr_in saddr;	
	
	int value;
	int n;
	char ch;
	
	gpgme_ctx_t ctx;
	gpgme_key_t key;
    	gpgme_error_t err;
    	gpgme_data_t in, out;
    	int ret;
	unsigned int textLength = strlen (argv[4]);

    	gpgme_sig_mode_t sigMode = GPGME_SIG_MODE_CLEAR;
	
	saddr_size = sizeof(saddr);
	
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
	

    	n = sscanf(argv[2], "%d%c", &value, &ch);
        /* Wenn sscanf keine Nummer konvertieren kann */
    	if (n != 1) {
		printf("Please provide correct port number!\n");
		usage();
		return 1;
    	}
	
	memset((char *) &saddr, 0, sizeof(saddr));
    	saddr.sin_family = AF_INET;
    	saddr.sin_port = htons(atoi(argv[2]));
     
    	if (inet_aton(argv[1] , &saddr.sin_addr) == 0){
        	printf("Address Setup Error\n");
		usage();
        	return 1;
    	}
 
    	/* Beginne Setup von GPGME */
	setlocale (LC_ALL, "");
    	gpgme_check_version (NULL);
    	gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
    	err = gpgme_engine_check_version (GPGME_PROTOCOL_OpenPGP);
    	if(err){
		printf("Error at engine check!\n");
		return 1;
	}    	
	/* Beende Setup von GPGME */
    
    	// Erstelle GPGME Kontext
    	err = gpgme_new (&ctx);
    	if(err){
		printf("Error at context creation!\n");
		return 1;
	}
	
    	/* Setze Context zu textmode */
    	gpgme_set_textmode (ctx, 1);
    	/* Schalte ASCII armor an */
    	gpgme_set_armor (ctx, 1);

	/* Suche nach dem Schluessel */
	err = gpgme_op_keylist_start (ctx, argv[3], 0);
	if(err){
		printf("Error at keylist setup!\n");
		gpgme_release (ctx);
		return 1;
	}
        err = gpgme_op_keylist_next (ctx, &key);
	gpgme_op_keylist_end (ctx);
	if(err){
		printf("Specified Key not found!\n");
		gpgme_release (ctx);
		return 1;
	}

	/* Fuege Schluessel fuer Signierung hinzu */
	err = gpgme_signers_add (ctx, key);
	gpgme_key_release (key);
	if(err){
		printf("Error at key adding for signing!\n");
		gpgme_release (ctx);
		return 1;
	}
	
    	/* Erschaffe Datenobjekte */
    	err = gpgme_data_new_from_mem (&in, argv[4], textLength, 0);
        if(err){
		printf("Error at data creation for input!\n");
		gpgme_release (ctx);
		return 1;
	}
    	err = gpgme_data_new (&out);
    	if(err){
		printf("Error at data creation for output!\n");
		gpgme_data_release (in);
		gpgme_release (ctx);
		return 1;
	}

    	/* Signiere */
    	err = gpgme_op_sign (ctx, in, out, sigMode);
    	if(err){
		printf("Error at signing!\n");
		gpgme_data_release (in);
		gpgme_data_release (out);
		gpgme_release (ctx);
		return 1;
	}

    	/* Beschaffe signierte Nachricht */
    	ret = gpgme_data_seek (out, 0, SEEK_SET);
    	if (ret){
        	if (gpgme_err_code_from_errno (errno)){
			printf("Error at rewinding data!\n");
			gpgme_data_release (in);
			gpgme_data_release (out);
			gpgme_release (ctx);
			return 1;
		}
	}
    	ret = gpgme_data_read (out, buffer, BUF_SIZE);
        if (ret){
        	if (gpgme_err_code_from_errno (errno)){
			printf("Error at reading data!\n");
			gpgme_data_release (in);
			gpgme_data_release (out);
			gpgme_release (ctx);
			return 1;
		}
	}
	
	/* Gebe signierte Nachricht aus */
        printf("%.*s\n", ret, buffer);

    	gpgme_data_release (in);
    	gpgme_data_release (out);
	gpgme_release (ctx);
	
	/* Oeffnen des Socket */
	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(sock < 0){
		printf("Socket Error\n");
		return 1;
	}
 
        /* Senden der Nachricht */
        if (sendto(sock, buffer, ret , 0 , (struct sockaddr *) &saddr, saddr_size)==-1){
		close(sock);
        	return 1;
        }
	
	close(sock);
	printf("Finished!\n");
	return 0;
}
