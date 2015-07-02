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

#define NCK 0
#define ACK 1
#define FIN 2
#define FINACK 3
#define alpha 0.875
#define beta 0.25

int sequence_number;
int accepted_sequence;
int RTT = 0;
int MDEV = 0;
int K = 4;
int RTO = 0;
int position_flag = 3;

int timeval_to_msec(struct timeval *t) { 
	return t->tv_sec*1000+t->tv_usec/1000;
}

void msec_to_timeval(int millis, struct timeval *out_timeval) {
	out_timeval->tv_sec = millis/1000;
	out_timeval->tv_usec = (millis%1000)*1000;
}

int current_msec() {
	struct timeval t;
	gettimeofday(&t,0);
	return timeval_to_msec(&t);
}

void update_RTT(int rtt){
	RTT = alpha * RTT +(1-alpha)*rtt;
}

void update_MDEV(int rtt){
	int distance = rtt-RTT;
	distance = distance>0?distance:0-distance;
	MDEV = (1-beta)*MDEV+beta*distance;
}

void update_RTO(){
	//RTO = RTT+K*MDEV;
	//RTO=MDEV;
	RTO=RTT;
}

int rel_connect(int socket,struct sockaddr_in *toaddr,int addrsize) {

	//need to be fixed about how to determine the time.

	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 1;
	//set time limitation for receiving
	if(setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv,sizeof(tv))){
		perror("setsockopt for receiving");
		return 0;
	}

	//set time limitation for sending
	if(setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv))){
		perror("setsockopt for sending");
		return 0;
	}
	connect(socket,(struct sockaddr*)toaddr,addrsize);
}

int rel_rtt(int socket) {
	return RTO;
}

void rel_send(int sock, void *buf, int len)
{
	position_flag = 0;
	
 	// make the packet = header + buf
	//
	//printf("%s\n", (char*)buf);
	//getchar();
	char packet[1400];
	struct tcp_hdr *hdr = (struct tcp_hdr*)packet;
	hdr->sequence_number = htonl(sequence_number);
	memcpy(hdr+1,buf,len); //hdr+1 is where the payload starts
	int length = sizeof(struct tcp_hdr)+len;
	if(buf==0&&len==0){
		hdr->ack_number = htonl(FIN);
		packet[sizeof(struct tcp_hdr)+1] = 0;
		length = sizeof(struct tcp_hdr);

		send(sock, packet, length, 0);
	}

	struct tcp_hdr *rtn = (struct tcp_hdr*)malloc(sizeof(struct tcp_hdr));
	int res;
	int rtt_start;
	int rtt_end, rtt;
	rtt_start = current_msec();
	int tmp1, tmp2;
	if(ntohl(hdr->ack_number) == FIN)
		tmp1 = current_msec();
	while(1){
		struct timeval tv;
		if(RTO!=0)
			msec_to_timeval(RTO, &tv);
		else
			msec_to_timeval(1, &tv);
		if(setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv))){
			perror("Setsockopt in rel_send");
			return;
		}
		//rtt_start = current_msec();
		//send(sock, packet, sizeof(struct tcp_hdr)+len, 0);
		fprintf(stderr, "Sending packet %d\n.", sequence_number);
		send(sock, packet, length, 0);
		res = recv(sock, rtn, sizeof(struct tcp_hdr), 0);
		//rtt_end = current_msec();
		//rtt = rtt_end-rtt_start;
		//update_MDEV(rtt);
		//update_RTT(rtt);
		//update_RTO();
		fprintf(stderr, "TIMEOUT: %d\n", rel_rtt(sock));
		fprintf(stderr, "res = %d\n", res);
		fprintf(stderr, "length = %d\n", sizeof(struct tcp_hdr));
		fprintf(stderr, "Return sequence: %d, Sending: %d, ack: %d\n", ntohl(rtn->sequence_number), ntohl(hdr->sequence_number),
				ntohl(rtn->ack_number));
/*		
		if(res==sizeof(struct tcp_hdr)){

			if((rtn->sequence_number == hdr->sequence_number))
			{
				if((ntohl(rtn->ack_number)==ACK))
					break;
				else if((ntohl(rtn->ack_number)==NCK))
					continue;
			}
			else if(ntohl(rtn->sequence_number)>ntohl(hdr->sequence_number))
				break;
			else if((rtn->sequence_number == hdr->sequence_number)&&
					(ntohl(rtn->ack_number)==FIN)&&(ntohl(hdr->ack_number)==FIN))
				break;
		}*/

		if(res == sizeof(struct tcp_hdr)){
			if(rtn->sequence_number == hdr->sequence_number){
				if(ntohl(rtn->ack_number)==ACK)
					break;
				else if(ntohl(rtn->ack_number)==NCK)
					continue;
				else if((ntohl(rtn->ack_number)==FIN)&&(ntohl(hdr->ack_number)==FIN))
					break;
			}
			else if(ntohl(rtn->sequence_number)<ntohl(hdr->sequence_number))
				continue;
			else
				break;
		}
		if(ntohl(hdr->ack_number)==FIN){
			tmp2 = current_msec();
			rtt = tmp2-tmp1;
			fprintf(stderr, "ENDING RTT = %d, %d\n", rtt, RTT);
			if(RTO!=0){
				if(rtt>RTO*10)
					break;
			}
			else
				if(rtt>1000)
					break;		

		}
			
	}
	rtt_end = current_msec();
	rtt = rtt_end - rtt_start;
	update_MDEV(rtt);
	update_RTT(rtt);
	update_RTO(RTO);
	sequence_number++;
	fprintf(stderr, "sequence_number = %d\n", sequence_number);
}

int rel_socket(int domain, int type, int protocol) {
	sequence_number = 0;
	accepted_sequence = 0;
	return socket(domain, type, protocol);
}

int rel_recv(int sock, void * buffer, size_t length) {

	position_flag = 1;
	char packet[MAX_PACKET];
	memset(&packet,0,sizeof(packet));
	struct tcp_hdr* hdr=(struct tcp_hdr*)packet;	

	struct sockaddr_in fromaddr;
	unsigned int addrlen=sizeof(fromaddr);
	int flag = 0;
	int tmp1, tmp2;
	while(1){
		int recv_count = recvfrom(sock, packet, MAX_PACKET, 0, (struct sockaddr*)&fromaddr, &addrlen);		

		// this is a shortcut to 'connect' a listening server socket to the incoming client.
		// after this, we can use send() instead of sendto(), which makes for easier bookkeeping
		if(connect(sock, (struct sockaddr*)&fromaddr, addrlen)) {
			perror("couldn't connect socket");
		}
		
		fprintf(stderr, "Got packet %d\n", ntohl(hdr->sequence_number));
		fprintf(stderr, "Here packet %d is accepted\n", accepted_sequence);
		//fprintf(stderr, "%s", packet+sizeof(struct tcp_hdr));
		// send back ACK;
		//char sndpkt[MAX_PACKET];
		//memset(&sndpkt, 0, sizeof(sndpkt));
		struct tcp_hdr * tmp = (struct tcp_hdr*) malloc(sizeof(struct tcp_hdr)*1);
		

/*	
		if(ntohl(hdr->sequence_number) <= accepted_sequence){

			//tmp->sequence_number = hdr->sequence_number;
			tmp->sequence_number = htonl(accepted_sequence);
			if(hdr->ack_number!=htonl(FIN))
				tmp->ack_number = htonl(ACK);
			else
				tmp->ack_number = htonl(FIN);

			if(ntohl(hdr->sequence_number)==accepted_sequence){
				
				
				fprintf(stderr, "Sending rsp for packet %d\n.", ntohl(hdr->sequence_number));
				send(sock, (const void *)tmp, sizeof(struct tcp_hdr), 0);
				
				//fprintf(stderr, "Send back ACK for packet %d\n", ntohl(hdr->sequence_number));
				//if(ntohl(hdr->sequence_number) == accepted_sequence){
				//fprintf(stderr, "Writing packet %d\n.", accepted_sequence);
				//fprintf(stderr, "%s%n\n", packet+sizeof(struct tcp_hdr), &test);
				//fprintf(stderr, "test = %d, %d\n", test, recv_count - sizeof(struct tcp_hdr));
				//fprintf(stderr, packet+sizeof(struct tcp_hdr), recv_count - sizeof(struct tcp_hdr));
				memcpy(buffer, packet+sizeof(struct tcp_hdr), recv_count - sizeof(struct tcp_hdr));
				accepted_sequence++;
				fprintf(stderr, "accepted_sequence = %d\n", accepted_sequence);
				//fprintf(stderr, "Return %d bytes\n", recv_count - sizeof(struct tcp_hdr));
				return recv_count - sizeof(struct tcp_hdr);
			}
			else{
				fprintf(stderr, "Sending NCK rps for packet %d\n", ntohl(tmp->
			}
		}
		else{
			tmp->sequence_number = htonl(accepted_sequence);
			tmp->ack_number = htonl(NCK);
			
			fprintf(stderr, "Sending NCK rsp for packet %d\n", ntohl(tmp->sequence_number));
			send(sock, (const void *)tmp, sizeof(struct tcp_hdr), 0);

		}*/


		if(ntohl(hdr->sequence_number)==accepted_sequence){
			tmp->sequence_number = htonl(accepted_sequence);
			if(hdr->ack_number != htonl(FIN))
				tmp->ack_number = htonl(ACK);

			else{
				tmp->ack_number = htonl(FIN);
				if(!flag){
					flag = 1;
					tmp1 = current_msec();
				}
			}


			fprintf(stderr, "Send ACK for packet %d\n", ntohl(hdr->sequence_number));
			send(sock, (const void*)tmp, sizeof(struct tcp_hdr), 0);

			memcpy(buffer, packet+sizeof(struct tcp_hdr), recv_count - sizeof(struct tcp_hdr));
			accepted_sequence++;
			//if(tmp->ack_number == htonl(FIN))
			//{
			//	send(sock, (const void*)tmp, sizeof(struct tcp_hdr), 0);
			//	send(sock, (const void*)tmp, sizeof(struct tcp_hdr), 0);
			//}
			fprintf(stderr, "accepted_sequence = %d\n", accepted_sequence);

			return recv_count - sizeof(struct tcp_hdr);				
		}
		else{
			tmp->sequence_number = htonl(accepted_sequence);
			tmp->ack_number = htonl(NCK);

			fprintf(stderr, "Send NCK for packet %d\n", accepted_sequence);
			send(sock, (const void *)tmp, sizeof(struct tcp_hdr), 0);
		}

		/*if(flag&&hdr->ack_number == htonl(FIN))
		{
			tmp2 = current_msec();
			if((tmp2-tmp1)>500)
				break;
		}*/
		recv_count = recv(sock, packet, MAX_PACKET, 0);
	}
}

int rel_close(int sock) {
	if(position_flag == 0)
		rel_send(sock, 0, 0); // send an empty packet to signify end of file
	else if(position_flag == 1);

	close(sock);
}

