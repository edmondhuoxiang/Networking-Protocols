#include <sys/time.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define ACK 0x1

struct hw6_hdr {
	uint32_t sequence_number;
	uint32_t ack_number;
	uint8_t flags;
};

#define MAX_PACKET 1400
#define MAX_SEGMENT (MAX_PACKET-sizeof(struct hw6_hdr))
#define MAX_BUFFER 1024 

int rel_socket(int domain, int type, int protocol);
int rel_connect(int socket,struct sockaddr_in *toaddr,int addrsize);
void rel_send(int sock, void *buf, int len);
int rel_recv(int sock, void * buffer, size_t length);
int rel_close(int sock);
int rel_rtt(int sock);

unsigned timeval_to_msec(struct timeval *t);
void msec_to_timeval(int millis, struct timeval *out_timeval);
unsigned  current_msec();

