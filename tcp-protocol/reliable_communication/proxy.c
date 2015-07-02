#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_PKT 1500

int port_b = 8080; //base port; if given proxy, sender, and reciver ports are taken automatically using base port 
int port_x = 8082; // (send to this port. listens on 8080)
int port_y = 8083; // (send to this port. receives on 8081)
in_addr_t host_x, host_y;
int latency = 100; // in milliseconds
int buffersize = 2; // in packetso
double txrate = 1024*1024; // bytes per second on the outgoing link
double forward_rate = 1.0; // probability
int seed = 123456789;
int long_term_latency = 0;
int long_term_packets = 0;

#ifndef FD_COPY
#define FD_COPY(f, t)   (void)(*(t) = *(f))
#endif

void usage() {
	printf("Usage: [-X <host X>] [-Y <host Y>] [ [[-x <port X>] [-y <port Y>]] | [-p <base port>] ]\n [-b <buffer size>] [-o outgoing link capacity] [-f <forwarding rate>] [-l <latency in ms>]\n");
	exit(1);
}

struct timeval time_after(int msec) {
	struct timeval t;
	
	gettimeofday(&t,0);
	t.tv_usec += 1000*msec;
	if(t.tv_usec > 1000000) {
		int secdiff = t.tv_usec / 1000000;
		t.tv_sec += secdiff;
		t.tv_usec -= secdiff * 1000000;
	}
	return t;
}

struct timeval time_from_now(struct timeval expiry) 
{
		 struct timeval t, res;	
		 gettimeofday(&t,0);
		 res.tv_sec = 0;
		 res.tv_usec = 0;

		 if((expiry.tv_sec < t.tv_sec) || (expiry.tv_sec==t.tv_sec &&  expiry.tv_usec <= t.tv_usec)) {
			 return res;
		 }
		 
		 if(expiry.tv_usec >= t.tv_usec) {
			 res.tv_usec = expiry.tv_usec - t.tv_usec;
			 res.tv_sec = expiry.tv_sec - t.tv_sec;
		 }
		 else {
			 res.tv_usec = 1000000 + expiry.tv_usec - t.tv_usec;
			 res.tv_sec = expiry.tv_sec - t.tv_sec - 1;
		 }

		 return res;
}

int timeval_to_ms(struct timeval t) {
		 return t.tv_sec*1000+t.tv_usec/1000;
}

int ms_from_now(struct timeval expiry) {
		 return timeval_to_ms(time_from_now(expiry));
}

int main(int argc, char** argv) {	
		 host_x = inet_addr("127.0.0.1");
		 host_y = inet_addr("127.0.0.1");
		 		 
		 char *optString = "d:X:x:Y:y:f:l:b:r:p:";
	int opt = getopt( argc, argv, optString );
	while( opt != -1 ) {
		switch( opt ) {     
		case 'b':
			buffersize = atoi(optarg)+1;
			if(buffersize<2) buffersize=2;
			break;
		case 'l':
			latency = atoi(optarg);
			break;
		case 'r':
			seed = atoi(optarg);
			break;
		case 'o':
			txrate = atof(optarg);
			break;
		case 'f':
			forward_rate = atof(optarg);
			break;
		case 'X':
			host_x = inet_addr(optarg); 
			break;
		case 'Y':
			host_y = inet_addr(optarg); 
			break;
		case 'x':
			port_x = atoi(optarg);
			break;
		case 'y':
			port_y = atoi(optarg);
			break;
		case 'p':
			port_b = atoi(optarg); 
			port_x = port_b+2;
			port_y = port_b+3;
			break;
		default:
			usage();
		}
		opt = getopt( argc, argv, optString );	
	}

	srandom(seed);
		
	int sock_x = socket(AF_INET, SOCK_DGRAM, 0);
	int sock_y = socket(AF_INET, SOCK_DGRAM, 0);
	if(sock_x < 0 || sock_y < 0) {
		perror("Creating socket failed: ");
		exit(1);
	}
	
	struct sockaddr_in addr; 	
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port_b); 
	addr.sin_addr.s_addr = INADDR_ANY;
	int addr_size = sizeof(addr);
	
	int res = bind(sock_x, (struct sockaddr*)&addr, sizeof(addr));
	if(res < 0) {
		perror("Binding port X");
		exit(1);
	}

	addr.sin_port = htons(port_b+1);
	res = bind(sock_y, (struct sockaddr*)&addr, sizeof(addr));
	if(res < 0) {
		perror("Binding port Y");
		exit(1);
	}


	struct packet {
		int len;
		int out_port;
		in_addr_t out_host;
		struct timeval tx_at;
		char buf[MAX_PKT];
	};

	// buffer size is meant to represent the total "volume of the pipes"
	struct packet packets[buffersize];
	int head  = 0;
	int tail = 0;
	
	fd_set readset;
	FD_ZERO(&readset);
	FD_SET(sock_x,&readset);	
	FD_SET(sock_y,&readset);	


	while(1) {
		fd_set rdyset;
		FD_COPY(&readset,&rdyset);

		struct timeval timeout = time_from_now(packets[head].tx_at);
		int rdy = select(FD_SETSIZE,&rdyset,0,0,((head==tail)?0:&timeout));
		if(rdy < 0) {
			perror("When selecting");
		}

		if(FD_ISSET(sock_x, &rdyset)) { 
			packets[tail].len = recv(sock_x, packets[tail].buf, 2000, 0);
			if(packets[tail].len<0) { perror("Receive failed");	exit(1); }			
			
			packets[tail].out_port = port_y; // in on X, out on Y.
			packets[tail].out_host = host_y; // in on X, out on Y.
			
			// figure out how long until the packet is finished exiting this queue
			int qsize = 0;
			for(int i=0;i<tail;i++)
				qsize+=packets[i].len;
			int qlatency = 1000 * qsize / txrate;

			// a bit of long-term latency variation
			if(long_term_packets == 0) {
				long_term_latency = (random()%(2*latency));
				long_term_packets = (random()%100);
			}
			long_term_packets--;

			// add some random delay to make the problem more interesting. This could be
			// seen as modeling the queuing delay incurred on other links along the path
			int dev = (random()%(latency/3))-latency/6;			

			int delay = latency + dev + long_term_latency + qlatency;

			// transmission time = now + latency ms
			packets[tail].tx_at = time_after(delay);
			if(((tail+1)%buffersize) != head)
				tail=(tail+1)%buffersize;
			else 
				printf("Dropped incoming packet due to full buffer.\n");
		}

		if(FD_ISSET(sock_y, &rdyset)) {
			packets[tail].len = recv(sock_y, packets[tail].buf, 2000, 0);
			if(packets[tail].len<0) { perror("Receive failed");	exit(1); }			
			
			packets[tail].out_port = port_x; // in on Y, out on X
			packets[tail].out_host = host_x;
			
			// transmission time = now + latency ms
			int dev = (random()%(latency/5))-latency/10;
			int delay = latency+dev;
			packets[tail].tx_at = time_after(delay);
			if(((tail+1)%buffersize) != head)
				tail=(tail+1)%buffersize;
			else 
				printf("Dropped incoming packet due to full buffer.\n");
		}

		// timer timed out
		if(head!=tail && ms_from_now(packets[head].tx_at)<=0) {		 
			addr.sin_port = htons(packets[head].out_port);
			addr.sin_addr.s_addr = packets[head].out_host;
			if(random() % 1000 < forward_rate*1000) {
				printf(".");
				if(sendto((packets[head].out_port==port_x?sock_x:sock_y),packets[head].buf,packets[head].len,0,(struct sockaddr*)&addr,sizeof(addr))<0) {
					perror("Couldn't send");
				}
			}
			else {
				printf("\nOops, dropped a packet.");
			}
			head=(head+1)%buffersize;			
		}

		if(head!=tail) {		
			timeout = time_from_now(packets[head].tx_at);
		} 
	}
	
	shutdown(sock_x,SHUT_RDWR);
	shutdown(sock_y,SHUT_RDWR);
}


