#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include "hw7.h"

int main(int argc, char **argv) {	
	if(argc<2) { fprintf(stderr,"Usage: hw7_receiver <base port>\n"); exit(1);}

	int sock = rel_socket(AF_INET, SOCK_DGRAM, 0);
	if(sock < 0) {
		perror("Creating socket failed: ");
		exit(1);
	}
	
	struct sockaddr_in addr; 	// internet socket address data structure
	addr.sin_family = AF_INET;
	addr.sin_port = htons(atoi(argv[1])); // byte order is significant
	addr.sin_addr.s_addr = INADDR_ANY;
	
	int res = bind(sock, (struct sockaddr*)&addr, sizeof(addr));
	if(res < 0) {
		perror("Error binding: ");
		exit(1);
	}

	int starttime = current_msec();
	int totalbytes = 0;

	char segment[MAX_SEGMENT];
	while(1) {
		int recv_count = rel_recv(sock, segment, MAX_SEGMENT);		
		if(recv_count == 0) break;
		totalbytes+=recv_count;
		
		// write out payload to stdout
		fwrite(segment,1,recv_count,stdout);							
	}

	int finished_msec = current_msec();

	fprintf(stderr,"\nReceived %d bytes in %.4f seconds, %.2f kB/s\n",
					totalbytes,
					(finished_msec-starttime)/1000.0,
					totalbytes/(float)(finished_msec-starttime));

	fprintf(stderr, "\nFinished receiving file, closing socket.\n");
	rel_close(sock);

	fflush(stdout);


	exit(0);
}


