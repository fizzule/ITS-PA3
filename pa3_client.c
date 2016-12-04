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
	
	gpgme_ctx_t ctx;
    	gpgme_error_t err;
    	gpgme_data_t in, out, result;
    	gpgme_verify_result_t verify_result;
    	gpgme_signature_t sig;
    	int tnsigs, nsigs;
    	int ret;
	int BUF_SIZE = 512;
	char buf[BUF_SIZE + 1];
	unsigned int textLength = strlen (argv[4]);
    	/* Set the GPGME signature mode
        	GPGME_SIG_MODE_NORMAL : Signature with data
        	GPGME_SIG_MODE_CLEAR  : Clear signed text
        	GPGME_SIG_MODE_DETACH : Detached signature */
    	gpgme_sig_mode_t sigMode = GPGME_SIG_MODE_CLEAR;
	
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
 
    	/* Begin setup of GPGME */
    	gpgme_check_version (NULL);
    	setlocale (LC_ALL, "");
    	gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
    	/* End setup of GPGME */

    	err = gpgme_engine_check_version (GPGME_PROTOCOL_GPGCONF);
    	if(err){
		close_all();
		return 1;
	}
    
    	// Create the GPGME Context
    	err = gpgme_new (&ctx);
    	if(err){
		close_all();
		return 1;
	}
    	// Set the context to textmode
    	gpgme_set_textmode (ctx, 1);
    	// Enable ASCII armor on the context
    	gpgme_set_armor (ctx, 1);

    	// Create a data object that contains the text to sign
    	err = gpgme_data_new_from_mem (&in, argv[4], textLength, 0);
        if(err){
		close_all();
		return 1;
	}

    	// Create a data object pointing to the out buffer
    	err = gpgme_data_new (&out);
    	if(err){
		close_all();
		return 1;
	}

    	// Create a data object pointing to the result buffer
   	err = gpgme_data_new (&result);
        if(err){
		close_all();
		return 1;
	}

    	// Sign the contents of "in" using the defined mode and place it into "out"
    	err = gpgme_op_sign (ctx, in, out, sigMode);
    	if(err){
		close_all();
		return 1;
	}

    	// Rewind the "out" data object
    	ret = gpgme_data_seek (out, 0, SEEK_SET);
    	// Error handling
    	//if (ret)
        //fail_if_err (gpgme_err_code_from_errno (errno));

    	// Read the contents of "out" and place it into buf
    	while ((ret = gpgme_data_read (out, buf, BUF_SIZE)) > 0) {
        	// Write the contents of "buf" to the console
        	fwrite (buf, ret, 1, stdout);
    	}

    	fwrite ("\n", 1, 1, stdout);

    	// Error handling
    	//if (ret < 0)
        //	fail_if_err (gpgme_err_code_from_errno (errno));

    	// Rewind the "out" data object
    	ret = gpgme_data_seek (out, 0, SEEK_SET);

    	// Perform a decrypt/verify action
    	err = gpgme_op_decrypt_verify (ctx, out, result);

   	 // Retrieve the verification result
    	verify_result = gpgme_op_verify_result (ctx);

    	// Error handling
    	//if (err != GPG_ERR_NO_ERROR && !verify_result)
        //	fail_if_err (err);

    	// Check if the verify_result object has signatures
    	/*if (verify_result && verify_result->signatures) {
        	// Iterate through the signatures in the verify_result object
        	for (nsigs=0, sig=verify_result->signatures; sig; sig = sig->next, nsigs++) {
            		fprintf(stdout, "Signature made with Key: %s\n", sig->fpr);
            		fprintf(stdout, "Created: %lu; Expires %lu\n", sig->timestamp, sig->exp_timestamp);
            		char *validity = sig->validity == GPGME_VALIDITY_UNKNOWN? "unknown":
                    		sig->validity == GPGME_VALIDITY_UNDEFINED? "undefined":
                    		sig->validity == GPGME_VALIDITY_NEVER? "never":
                    		sig->validity == GPGME_VALIDITY_MARGINAL? "marginal":
                    		sig->validity == GPGME_VALIDITY_FULL? "full":
                    		sig->validity == GPGME_VALIDITY_ULTIMATE? "ultimate": "[?]";
            		char *sig_status = gpg_err_code (sig->status) == GPG_ERR_NO_ERROR? "GOOD":
                    		gpg_err_code (sig->status) == GPG_ERR_BAD_SIGNATURE? "BAD_SIG":
                    		gpg_err_code (sig->status) == GPG_ERR_NO_PUBKEY? "NO_PUBKEY":
                    		gpg_err_code (sig->status) == GPG_ERR_NO_DATA? "NO_SIGNATURE":
                    		gpg_err_code (sig->status) == GPG_ERR_SIG_EXPIRED? "GOOD_EXPSIG":
                    		gpg_err_code (sig->status) == GPG_ERR_KEY_EXPIRED? "GOOD_EXPKEY": "INVALID";
            		fprintf(stdout, "Validity: %s; Signature Status: %s", validity, sig_status);
            		fwrite("\n", 1, 1, stdout);
            		tnsigs++;
        	}
    	}*/

    	//if (err != GPG_ERR_NO_ERROR && tnsigs < 1)
        //	fail_if_err(err);

    	// Release the "in" data object
    	gpgme_data_release (in);
    	// Release the "out" data object
    	gpgme_data_release (out);

    	// Release the context
	gpgme_release (ctx);
	
	
	
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
 
        //send the message
        if (sendto(sock, argv[4], strlen(argv[4]) , 0 , (struct sockaddr *) &saddr, saddr_size)==-1){
            	close_all();
        	return 1;
        }
 
	close_all();
	printf("Finished!\n");
	return 0;
}
