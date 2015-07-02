#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include "tcp.h"

int main(int argc, char **argv) {	
	if(argc<3) { fprintf(stderr,"Usage: tcp_receiver <remote host> <base port>\n"); exit(1);}

	int sock = rel_socket(AF_INET, SOCK_DGRAM, 0);
	if(sock < 0) {
		perror("Creating socket failed: ");
		exit(1);
	}
	
	struct sockaddr_in addr; 	// internet socket address data structure
	addr.sin_family = AF_INET;
	addr.sin_port = htons(atoi(argv[2])+3); // byte order is significant
	addr.sin_addr.s_addr = INADDR_ANY;
	
	int res = bind(sock, (struct sockaddr*)&addr, sizeof(addr));
	if(res < 0) {
		perror("Error binding: ");
		exit(1);
	}

	char segment[MAX_SEGMENT];
	while(1) {
		int recv_count = rel_recv(sock, segment, MAX_SEGMENT);		
		if(recv_count == 0) break;
		
		//printf("\nIn receiver, return %d bytes\n", recv_count);
		//getchar();
		// write out payload to stdout
		fwrite(segment,1,recv_count,stdout);							
	}

	fprintf(stderr, "\nFinished receiving file, closing socket.\n");
	rel_close(sock);

	fflush(stdout);


	exit(0);
}


