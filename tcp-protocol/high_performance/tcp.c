#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <math.h>
#include "tcp.h"

int * sent_time;

unsigned int rtt;
unsigned int deviation;
struct timeval timeout;

struct sockaddr_in peeraddr;

int sequence_number;
int expected_sequence_number = 0;


char * send_buffer;
int sequence_base;
int window_size;
int * retx;
int * packet_length;
struct timeval * packet_timeout;
int threshold = 2;
int congestion_flag = 0;
int lost_number = 0;
//int * sent_time;
int time_start;
int timeout_time;
int first_lost=0;
int min(int a, int b){
	return a<b?a:b;
}

unsigned timeval_to_msec(struct timeval *t) { 
	return t->tv_sec*1000+t->tv_usec/1000;
}

void msec_to_timeval(int millis, struct timeval *out_timeval) {
	out_timeval->tv_sec = millis/1000;
	out_timeval->tv_usec = (millis%1000)*1000;
}

unsigned current_msec() {
	struct timeval t;
	gettimeofday(&t,0);
	return timeval_to_msec(&t);
}

/* updates rtt and deviation estimates based on new sample */
void update_rtt(unsigned this_rtt) {
	// if this is the first packet, make an 'educated guess' as to the rtt and deviation
	if(sequence_number==0) {
		rtt = this_rtt;
		deviation = this_rtt/2;
	}
	else {
	  deviation = 0.7*deviation + 0.3*(abs(this_rtt - rtt));
	  rtt = 0.8*rtt + 0.2*this_rtt;
	}
	msec_to_timeval(rtt+4*deviation,&timeout);
}

int rel_connect(int socket,struct sockaddr_in *toaddr,int addrsize) {
		 peeraddr=*toaddr;
		 return 0;
}

int rel_rtt(int sock) {
		 return rtt;
}
void print_window()
{
	struct hw6_hdr *tmp;
	fprintf(stderr, "\n***************Window_size = %d*********************\n", window_size);
	fprintf(stderr, "sequence: %d\t     base: %d     threshold: %d\n", sequence_number, sequence_base, threshold);

	for(int i=0;i<sequence_number-sequence_base;i++){
		if(i==window_size)
			fprintf(stderr,"\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
		tmp = (struct hw6_hdr*)(send_buffer+(i*MAX_PACKET*sizeof(char)));
		fprintf(stderr, "\r\n%d th packet in window is Packet %d", i, ntohl(tmp->sequence_number));
	}
}

void resend_all(int sock)
{
	char tmp_packet[MAX_PACKET];
	char * pointer1 = tmp_packet;
	char * pointer2;
	time_start = current_msec();

	int limit = 0;
	if(congestion_flag == 100)
		limit = 25;
	else
	{
		limit = sequence_number-sequence_base;
		if(window_size<limit)
			limit = window_size;
	}
	//msec_to_timeval(min(5000,2*timeval_to_msec(&timeout)),&timeout);
	for(int i=0;i<limit; i++){
		//fprintf(stderr,"\r\nPacket %d with rtt %d dev timeout %d ms           \n",i+sequence_base,rtt,deviation,timeval_to_msec(&timeout));
		//fprintf(stderr,"\r\nSend one more time");

	//	if(timeval_to_msec(&packet_timeout[i])>(current_msec()-sent_time[i])){
			pointer2 = send_buffer+(i*MAX_PACKET*sizeof(char));
			memcpy(pointer1, pointer2, MAX_PACKET*sizeof(char));
			
			struct hw6_hdr * pointer3 = (struct hw6_hdr*)pointer1;
			printf("***Sending Packet %d %d bytes****\n", ntohl(pointer3->sequence_number), packet_length[i]);
			//fprintf(stderr,"####Resending Packet %d ####\n",ntohl(pointer3->sequence_number));
			sendto(sock, pointer1, sizeof(struct hw6_hdr)+packet_length[i], 0, (struct sockaddr*)&peeraddr, sizeof(peeraddr));
			
			retx[i]=1;
			sent_time[i]=current_msec();
			int time;
			time = timeval_to_msec(&packet_timeout[i]);
			msec_to_timeval(time/2, &packet_timeout[i]);
	//	}
	}
}
void update_window_size(int signal)
{

	if(first_lost==1){
			window_size = congestion_flag;
		}
		return;
	/*
	if(signal == 1)
	{
		if(window_size<MAX_BUFFER)
		{
			if(window_size < threshold)
				window_size = window_size*2;
			else
				window_size = window_size+1;
		}
	}
	else if(signal == 0){
		if(window_size>4)
			threshold = window_size/2;
		else
			threshold = 2;

		window_size = threshold+3;
		congestion_flag = 1;
	}

	if(first_lost==1)
		if(congestion_flag!=100)
			window_size = congestion_flag;

	*/
}

void move_send_buffer(int ack_number)
{
	char * tmp_pointer=send_buffer;
	int * tmp;
	struct timeval * tmp1;
	memmove(tmp_pointer,tmp_pointer+(ack_number-sequence_base+1)*MAX_PACKET*sizeof(char),
			(sequence_number-ack_number)*MAX_PACKET*sizeof(char));
	tmp = retx;
	memmove(tmp, tmp+(ack_number-sequence_base+1), (sequence_number-ack_number)*sizeof(int));
	tmp = packet_length;
	memmove(tmp, tmp+(ack_number-sequence_base+1), (sequence_number-ack_number)*sizeof(int)); 
	tmp = sent_time;
	memmove(tmp, tmp+(ack_number-sequence_base+1), (sequence_number-ack_number)*sizeof(int));
	tmp1 = packet_timeout;
	memmove(tmp1, tmp1+(ack_number-sequence_base+1), (sequence_number-ack_number)*sizeof(struct timeval));
}




void rel_send(int sock, void *buf, int len)
{
 	// make the packet = header + buf
	char packet[1400];
	struct hw6_hdr *hdr = (struct hw6_hdr*)packet;
	memset(hdr,0,sizeof(struct hw6_hdr));
	hdr->sequence_number = htonl(sequence_number);
	memcpy(hdr+1,buf,len);
	int eof_flag=0;
	int eof_time;


	if(len!=0){
		
		fprintf(stderr,"\rPacket %d with rtt %d dev %d timeout %d ms           \n",sequence_number,rtt, deviation,timeval_to_msec(&timeout));
		printf("Sending packet %d %d bytes\n", sequence_number, len);
		sendto(sock, packet, sizeof(struct hw6_hdr)+len, 0,(struct sockaddr*)&peeraddr,sizeof(peeraddr));
		memcpy(send_buffer+((sequence_number-sequence_base)*MAX_PACKET*sizeof(char)), hdr, MAX_PACKET);
		retx[sequence_number-sequence_base] = 0;
		packet_timeout[sequence_number - sequence_base] = timeout;
		packet_length[sequence_number - sequence_base] = len;
		sent_time[sequence_number-sequence_base]=current_msec();
		//if sequence_number==sequence_base, means there is no packet in buffer, so begin timer
		if(sequence_number==sequence_base)
			//time_start = sent_time[sequence_number-sequence_base];
			time_start=current_msec();
		//if the # of packet outstanding without ACK in buffer is less than winow_size, return to
		//get more packet
		sequence_number++;
		if(sequence_number-sequence_base < window_size)
			return;
	}
	else{
		fprintf(stderr, "\r*************End Packet is prepared to be send*******************\n");
		if(sequence_base == sequence_number){//nothing left in buffer to send
			fprintf(stderr, "\r\nSend EOF packet");
			fprintf(stderr, "\r\nPacket %d with rtt %d dev %d time %d ms           \n", 
					sequence_number,rtt, deviation,timeval_to_msec(&timeout));
			memcpy(send_buffer, hdr, MAX_PACKET*sizeof(char));

			retx[0]=0;
			packet_length[0]=len;
			packet_timeout[0]= timeout;
			sequence_number++;	
			//sent_time[0]=current_msec();
			eof_flag=1;
			eof_time = current_msec();
		}
	}
	// repeatedly send it until we get an ack
	while(1) {
		//int sent_time = current_msec();
		
		fprintf(stderr, "****window size: %d sequence_number %d sequence_base %d****\n", window_size, sequence_number, sequence_base);
		fprintf(stderr, "         threshold = %d\n", threshold);
		fprintf(stderr, " lost_number = %d\n", lost_number);
		fd_set readset;
		FD_ZERO(&readset);
		FD_SET(sock,&readset); 

		int duration = timeval_to_msec(&timeout)-(current_msec()-time_start);
		struct timeval t; // select changes the timeout parameter on some platforms, so make a copy

		int k = 0;
			for(int i = 0; i< sequence_number-sequence_base && i < window_size; i++){
				if(timeval_to_msec(&packet_timeout[i])<timeval_to_msec(&packet_timeout[k]))
					k = i;
			}

			t = packet_timeout[k];
			//t=timeout;
			fprintf(stderr, "rtt: %d    timeout:%d\n", rtt, timeval_to_msec(&timeout));
			fprintf(stderr, "Select waiting time: %d\n", timeval_to_msec(&t));

			int rdy = select(FD_SETSIZE,&readset,0,0,&t);

			if(rdy==0) {
				fprintf(stderr, "Timeout!!!\n%d %d\n", len, eof_flag);
				// if we timed out, send again double the timeout value
				msec_to_timeval(min(500,timeval_to_msec(&timeout)), &timeout);
				/*fprintf(stderr,"\rPacket %d with rtt %d dev %d timeout %d ms           ",sequence_number,rtt, deviation,timeval_to_msec(&timeout));
				sendto(sock, packet, sizeof(struct hw6_hdr)+len, 0,(struct sockaddr*)&peeraddr,sizeof(peeraddr));
				ret=1;*/
				if(first_lost==0)
					lost_number++;
				timeout_time++;
				resend_all(sock);
				if(timeout_time%3==0)
					update_window_size(0);
				if(len==0&&eof_flag==1)
					if(current_msec()-eof_time>200)
						break;
			}
			else if(rdy==-1) {
				perror("select error");
				return ;
			}
			else {
				char incoming[1400];
				struct sockaddr_in from_addr;
				unsigned int addrsize = sizeof(from_addr);
				int recv_count=recvfrom(sock,incoming,1400,0,(struct sockaddr*)&from_addr,&addrsize);
				if(recv_count<0) {
					perror("When receiving packet.");
					return;
				}
				
				struct hw6_hdr *hdr = (struct hw6_hdr*)incoming;

				if(ntohl(hdr->ack_number)>=30&&first_lost==0){
					first_lost = 1;
					//if(lost_number<=10)
					//	congestion_flag = 100;
					if(lost_number < 100)
						congestion_flag = 10;
					else 
						congestion_flag = 2;

				}

				if(ntohl(hdr->ack_number)>500)
					congestion_flag = 100;

				fprintf(stderr, "Receive an ACK for Packet %d\n", ntohl(hdr->ack_number));
				//printf("Receive an ACK for Packet %d\n", ntohl(hdr->ack_number));

			if(ntohl(hdr->ack_number)<sequence_base)
			{
				if(current_msec()-sent_time[0]>rtt){
					printf("There is an ACK receive more than 1 time\n");
					char tmp_packet[MAX_PACKET];
					char * pointer1 = tmp_packet;
					char * pointer2 = send_buffer;
					memcpy(pointer1, pointer2, MAX_PACKET);
					struct hw6_hdr * pointer3=(struct hw6_hdr*)pointer1;
					fprintf(stderr,"Resending Packet %d *********\n", ntohl(pointer3->sequence_number));
					//printf("***Sending Pakcet %d***\n", ntohl(pointer3->sequence_number));
					sendto(sock, pointer1, sizeof(struct hw6_hdr)+packet_length[0],0,(struct sockaddr*)&peeraddr,sizeof(peeraddr));
					sent_time[0] = current_msec();
				}
				if(first_lost==0)
				lost_number++;

			}
			// if this is an ack for our present packet, update the rtt and exit
			else if(ntohl(hdr->ack_number) < sequence_number) {
				//time_start = current_msec();
				//
				update_window_size(1);
				if(!retx[ntohl(hdr->ack_number)-sequence_base]){
					//printf("It is an ACK for nomarl Packet,its Rtt is %d\n", current_msec()-sent_time[ntohl(hdr->ack_number)-sequence_base]);
						//fprintf(stderr, "rtt for packet %d is %d\n",ntohl(hdr->ack_number),sent_time[ntohl(hdr->ack_number)-sequence_base]);
					//update_rtt(current_msec()-sent_time[ntohl(hdr->ack_number)-sequence_base]);
					update_rtt(current_msec()-sent_time[ntohl(hdr->ack_number)-sequence_base]);
				}
				else
					printf("It is an ACK for OUTIME packet\n");
				time_start = current_msec();
				//update_window_size(1);
				//sequence_number++;
				move_send_buffer(ntohl(hdr->ack_number));
				sequence_base=ntohl(hdr->ack_number)+1;
				if(len!=0)
					if((sequence_number-sequence_base)<window_size)
						break;

				if(len==0&&sequence_number==sequence_base&&eof_flag !=1)
				{
					fprintf(stderr, "\r\tSend EOF packet\n");
					fprintf(stderr, "\r\nPacket %d with rtt %d dev %d timeout %d ms          \n", sequence_number,rtt,deviation,timeval_to_msec(&timeout));
					//printf("***Sending packet %d***\n", sequence_number);
					sendto(sock,packet,sizeof(struct hw6_hdr)+len,0,(struct sockaddr*)&peeraddr,sizeof(peeraddr));

					memcpy(send_buffer,packet,MAX_PACKET*sizeof(char));

					retx[0];
					packet_length[0]=len;
					//sent_time[0]=current_msec();
					sequence_number++;
					eof_flag=1;
					eof_time = current_msec();
				}
				//resend_all(sock);
			}
			
			// if it's not an ack, it's the end of the stream. ACK it. 
			if(! (hdr->flags & ACK)) {
				// ack whatever we have so far
				struct hw6_hdr ack;
				ack.flags = ACK;
				if(ntohl(hdr->sequence_number) == expected_sequence_number) {
					expected_sequence_number++;
				}
				else {
					fprintf(stderr,"Unexpected non-ACK in rel_send(), size %d. Acking what we have so far. \n",recv_count);
				}
				ack.ack_number = htonl(expected_sequence_number-1);
				sendto(sock, &ack, sizeof(ack), 0,(struct sockaddr*)&peeraddr,sizeof(peeraddr));
				break;
			}		 
		}
		if(len==0&&eof_flag==1)
			if(current_msec()-eof_time>200)
				break;
		
	}
}

int rel_socket(int domain, int type, int protocol) {
	/* start out with large timeout and rtt values */
	rtt = 500;
	deviation = 50;
	timeout.tv_sec = 0; 
	timeout.tv_usec = 700000; // rtt + 4*deviation ms
	sequence_number = 0;

	//inintialize something new
	sequence_number = 0;
	sequence_base = 0;
	window_size = 10;

	send_buffer = (char*)malloc(sizeof(char)*MAX_PACKET*MAX_BUFFER);
	packet_length = (int*)malloc(sizeof(int)*MAX_BUFFER);
	retx = (int*)malloc(sizeof(int)*MAX_BUFFER);
	sent_time = (int*)malloc(sizeof(int)*MAX_BUFFER);
	packet_timeout = (struct timeval*)malloc(sizeof(struct timeval)*MAX_BUFFER);

	return socket(domain, type, protocol);
}

int rel_recv(int sock, void * buffer, size_t length) {
	char packet[MAX_PACKET];
	memset(&packet,0,sizeof(packet));
	struct hw6_hdr* hdr=(struct hw6_hdr*)packet;	

	while(1) {
		// remember these so that we can close an incoming socket as well as outgoing sockets
		unsigned int addrlen=sizeof(peeraddr);

		int recv_count = recvfrom(sock, packet, MAX_PACKET, 0, (struct sockaddr*)&peeraddr, &addrlen);		
		if(recv_count<0) { break; }

 		// if we got the expected packet, send an ACK and return data
 		if(ntohl(hdr->sequence_number) == expected_sequence_number) {
 						
 			struct hw6_hdr ack;
			ack.flags = ACK;
			ack.ack_number = hdr->sequence_number;
 			sendto(sock, &ack, sizeof(ack), 0, (struct sockaddr*)&peeraddr, addrlen);
 			
 			expected_sequence_number++;
			fprintf(stderr, "Recv sequence number:%d                   \r\n",ntohl(hdr->sequence_number));
			fprintf(stderr, "Next sequence number: %d                  \r\n",expected_sequence_number);
 			if(recv_count != sizeof(struct hw6_hdr))
				memcpy(buffer, packet+sizeof(struct hw6_hdr), recv_count - sizeof(struct hw6_hdr));
 			return recv_count - sizeof(struct hw6_hdr);
 		}
		else {
			// ack whatever we have so far
			struct hw6_hdr ack;
			ack.flags = ACK;
			ack.ack_number = htonl(expected_sequence_number-1);
			//printf( "Recv an addtional sequence number:%d            \r\n",ntohl(hdr->sequence_number));
			sendto(sock, &ack, sizeof(ack), 0, (struct sockaddr*)&peeraddr, addrlen);	 
		}
	}
}


int rel_close(int sock) {

	// an empty packet signifies end of file
	rel_send(sock,0,0);

	fprintf(stderr,"\nSent EOF. Now in final wait state.\n");

	struct timeval t;
	t.tv_sec = 2;
	t.tv_usec = 0;

	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &t, sizeof(t));
	int wait_start = current_msec();


	char packet[MAX_PACKET];
	memset(&packet, 0, sizeof(packet));
	struct hw6_hdr * hdr = (struct hw6_hdr*)packet;
	// wait for 2 seconds
	while(current_msec() - wait_start < 200) {	
		// remember these so that we can close an incoming socket as well as outgoing sockets
		unsigned int addrlen=sizeof(peeraddr);

		int recv_count = recvfrom(sock, packet, MAX_PACKET, 0, (struct sockaddr*)&peeraddr, &addrlen);		
		if(recv_count<0) { break; }

 		// if we got the expected packet, send an ACK and return data
 		if(ntohl(hdr->sequence_number) == expected_sequence_number) {
 						
 			struct hw6_hdr ack;
			ack.flags = ACK;
			ack.ack_number = hdr->sequence_number;
 			sendto(sock, &ack, sizeof(ack), 0, (struct sockaddr*)&peeraddr, addrlen);
 			
 			expected_sequence_number++;
			fprintf(stderr,"Recv sequence number:%d                   \r\n",ntohl(hdr->sequence_number));
			fprintf(stderr,"Next sequence number: %d                  \r\n",expected_sequence_number);
 			break;
 		}
		else {
			// ack whatever we have so far
			struct hw6_hdr ack;
			ack.flags = ACK;
			ack.ack_number = htonl(expected_sequence_number-1);
			sendto(sock, &ack, sizeof(ack), 0, (struct sockaddr*)&peeraddr, addrlen);	 
		}
	}

	close(sock);
}

