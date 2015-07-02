#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "tcp.h"

int main(int argc, char** argv) {	
	if(argc<3) { fprintf(stderr,"Usage: tcp_sender <remote host> <base port>\n"); exit(1);}

	struct sockaddr_in addr; 
	addr.sin_family = AF_INET;

	int sock = rel_socket(AF_INET, SOCK_DGRAM, 0);
	if(sock < 0) {
		perror("Creating socket failed: ");
		exit(1);
	}

	addr.sin_port = htons(atoi(argv[2])+2);
	addr.sin_addr.s_addr = INADDR_ANY;
	if(bind(sock,(struct sockaddr*)&addr,sizeof(addr))) {
		perror("When binding");
	}

	addr.sin_port = htons(atoi(argv[2])); 
	addr.sin_addr.s_addr = inet_addr(argv[1]);	

	// this simply stores the address for the socket, so we don't have to use sendto()
	if(rel_connect(sock, &addr,sizeof(addr))) {
			perror("When connecting");
	}	

	char buf[MAX_PACKET-sizeof(struct tcp_hdr)];	
	memset(&buf,0,sizeof(buf));

	int starttime = current_msec();
	int totalbytes = 0;

	int readbytes;
	while(readbytes=fread(buf,1,sizeof(buf),stdin)) {
		totalbytes+=readbytes;
		rel_send(sock, buf, readbytes);							 
		printf("sent a packet\n");
	}

	int finished_msec = current_msec();
	fprintf(stderr,"\nFinished sending, closing socket.\n");
	rel_close(sock);

	fprintf(stderr,"\nSent %d bytes in %.4f seconds, %.2f kB/s\n",
					totalbytes,
					(finished_msec-starttime)/1000.0,
					totalbytes/(float)(finished_msec-starttime));
	fprintf(stderr,"Estimated RTT: %d ms\n",
					rel_rtt(sock));
}

