#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include "dns.h"

static int debug=0, nameserver_flag=0;
static int flag = 0;

static char name[255];
static char tmp_addr[255];
static int level = 0;
static char ip_address[255];

void usage() {
	printf("Usage: dns_resovler [-d] -n nameserver -i domain/ip_address\n\t-d: debug\n");
	exit(1);
}

/* constructs a DNS query message for the provided hostname */
int construct_query(uint8_t* query, int max_query, char* hostname) {
	memset(query,0,max_query);

	in_addr_t rev_addr=inet_addr(hostname);
	if(rev_addr!=INADDR_NONE) {
		static char reverse_name[255];		
		sprintf(reverse_name,"%d.%d.%d.%d.in-addr.arpa",
						(rev_addr&0xff000000)>>24,
						(rev_addr&0xff0000)>>16,
						(rev_addr&0xff00)>>8,
						(rev_addr&0xff));
		hostname=reverse_name;
	}

	// first part of the query is a fixed size header
	struct dns_hdr *hdr = (struct dns_hdr*)query;

	// generate a random 16-bit number for session
	uint16_t query_id = (uint16_t) (random() & 0xffff);
	hdr->id = htons(query_id);
	// set header flags to request recursive query
	hdr->flags = htons(0x0100);	
	// 1 question, no answers or other records
	hdr->q_count=htons(1);

	// add the name
	int query_len = sizeof(struct dns_hdr); 
	int name_len=to_dns_style(hostname,query+query_len);
	query_len += name_len; 
	
	// now the query type: A or PTR. 
	uint16_t *type = (uint16_t*)(query+query_len);
	/*if(rev_addr!=INADDR_NONE)
		*type = htons(12);
	else
		*type = htons(1);*/

    if(strstr(hostname, ".in-addr.arpa")!=NULL)
        *type = htons(12);
    else
        *type = htons(1);
	query_len+=2;

	// finally the class: INET
	uint16_t *class = (uint16_t*)(query+query_len);
	*class = htons(1);
	query_len += 2;
 
	return query_len;	
}
int is_ipaddr(char * addr)
{
    char buffer[64];
    char *tmp, *tp;
    tmp = strstr(addr, ".");
    for(tp = addr; tp < tmp; tp++){
        if(isalpha(*tp))
            return 0;
    }
    return 1;
}

int reverse_ip(char * hostname)
{
    if(!is_ipaddr(hostname)){
        printf("%s is not a ip address\n", hostname);
        return 0;
    }
    char buffer[255];
    memset(buffer, 255, '\0');
    char * tmp, * tmp2;
    int length = strlen(hostname);
    tmp= hostname + length;
    for(tmp2 = tmp; tmp2>=hostname; tmp2--){
        if(*tmp2 == '.'||tmp2 == hostname){
            *tmp = '\0';
            if(tmp2 == hostname)
                strcat(buffer, tmp2);
            else{
                if(tmp == hostname+length)
                    strcpy(buffer, tmp2+1);
                else
                    strcat(buffer, tmp2+1);
            }
            tmp = tmp2;
            strcat(buffer, ".");
        }
    }
    //strcat(buffer, tmp2);
    strcat(buffer, "in-addr.arpa");
    hostname = realloc(hostname, strlen(buffer)+1);
    strcpy(hostname, buffer);
}
int get_answer(uint8_t * answerbuf, char * nameserver, char * hostname)
{
    int sock; 
    uint8_t query[1500];
    int query_len;
    struct sockaddr_in addr;
    int send_count;
    int rec_count;
    struct timeval timeout;
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    level += 1;

    //using name server address to create a socket
    in_addr_t nameserver_addr = inet_addr(nameserver);
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0){
        perror("Creating socket failed: ");
        return -1;
    }
    if(setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout))<0){
        perror("Cannot set socket options.");
        return -1;
    }

    // construct the query message
    query_len = construct_query(query, 1500, hostname);

    // internet socket address data structure
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53); //port 53 for DNS
    addr.sin_addr.s_addr = nameserver_addr; //destination address

    send_count = sendto(sock, query, query_len, 0,
            (struct sockaddr *)&addr, sizeof(addr));
    if(send_count < 0){
        perror("Send failed");
        return -1;
    }

    // await the response
    rec_count = recv(sock, answerbuf, 1500, 0);
    if(rec_count==-1){
        if(errno == EAGAIN){
            perror("Name server time out");
            return -1;
        }
    }
    shutdown(sock, SHUT_RDWR);
    close(sock);
    return 1;
}

int get_ipaddr2(char * hostname, char * res_string){

    FILE * root_fp;
    if((root_fp = fopen("root-servers.txt", "r")) == NULL){
        perror("Cannot open root-servers.txt");
        exit (1);
    }
    char buffer[255];
    int length;
    while(fgets(buffer, 255, root_fp)!=0){
        length = strlen(buffer);
        buffer[length-1] = '\0';
        if(get_ipaddr(hostname, buffer, res_string)==1)
            break;
    }
}

int main(int argc, char** argv)
{
	if(argc<2) usage();
	
	char *hostname=0;
	char *nameserver=0;
    char * tmp_ptr;
	char *optString = "-d-n:-i:";
 	int opt = getopt( argc, argv, optString );
	
	while( opt != -1 ) {
		switch( opt ) {      
		case 'd':
			debug = 1; 
			break;
		case 'n':
			nameserver_flag = 1; 
			nameserver = optarg;
			break;	 		
		case 'i':
			hostname = optarg;
			break;	
		case '?':
			usage();
			exit(1);               
		default:
			usage();
			exit(1);
		}
		opt = getopt( argc, argv, optString );
	}

    tmp_ptr = hostname;
    hostname = (char *)malloc((strlen(hostname)+1)*sizeof(char));
    strcpy(hostname, tmp_ptr);
		
	if(!hostname) {
		usage();
		exit(1);
	}

    if(is_ipaddr(hostname))
	{
		strcpy(ip_address, hostname);
        reverse_ip(hostname);
	}

    printf("Host name is %s\n", hostname);
    strcpy(name, hostname);

	char * res_string;

    if(nameserver){
        if(get_ipaddr(hostname, nameserver, res_string)==-1)
            printf("Cannot solved by %s\n", nameserver);
    }
    else
        get_ipaddr2(hostname, res_string);

}

int get_ipaddr(char *hostname, char * nameserver, char * res_string)
{
	uint8_t answerbuf[1500];
	char *local_string;
    int res;
    
    res = get_answer(answerbuf, nameserver, hostname);
    if(res < 0){
        perror("Cannot get data from name server.");
        return -1;
    }

	
	
	// parse the response to get our answer
	struct dns_hdr *ans_hdr=(struct dns_hdr*)answerbuf;
	uint8_t *answer_ptr = answerbuf + sizeof(struct dns_hdr);
	
	// now answer_ptr points at the first question. 
	int question_count = ntohs(ans_hdr->q_count);
	int answer_count = ntohs(ans_hdr->a_count);
	int auth_count = ntohs(ans_hdr->auth_count);
	int other_count = ntohs(ans_hdr->other_count);

	// skip past all questions
	int q;
	for(q=0;q<question_count;q++) {
		char string_name[255];
		memset(string_name,0,255);
		int size=from_dns_style(answerbuf,answer_ptr,string_name);
		answer_ptr+=size;
		answer_ptr+=4; //2 for type, 2 for class
	}

	int a;
	int got_answer=0;


	// now answer_ptr points at the first answer. loop through
	// all answers in all sections
	for(a=0;a<answer_count+auth_count+other_count;a++) {
		// first the name this answer is referring to 
		char string_name[255];
		int dnsnamelen=from_dns_style(answerbuf,answer_ptr,string_name);
		answer_ptr += dnsnamelen;

		// then fixed part of the RR record
		struct dns_rr* rr = (struct dns_rr*)answer_ptr;
		answer_ptr+=sizeof(struct dns_rr);

		const uint8_t RECTYPE_A=1;
		const uint8_t RECTYPE_NS=2;
		const uint8_t RECTYPE_CNAME=5;
		const uint8_t RECTYPE_SOA=6;
		const uint8_t RECTYPE_PTR=12;
		const uint8_t RECTYPE_AAAA=28;

		if(htons(rr->type)==RECTYPE_A) {
			printf("The name %s resolves to IP addr: %s\n",
						 string_name,
						 inet_ntoa(*((struct in_addr *)answer_ptr)));
			got_answer=1;

            if(strcmp(hostname, string_name)!=0)
            {
               get_ipaddr(hostname, inet_ntoa(*((struct in_addr *)answer_ptr)), res_string);
            }
            else{
                res_string = (char *)malloc((strlen(inet_ntoa(*((struct in_addr *)answer_ptr))+1))*sizeof(char));
                strcpy(tmp_addr,  (char*)inet_ntoa(*((struct in_addr *)answer_ptr)));
            }
                return 1;

		}
		
		else if(htons(rr->type)==RECTYPE_NS ) {
			char ns_string[255];
			int ns_len=from_dns_style(answerbuf,answer_ptr,ns_string);
			if(debug)
				printf("The name %s can be resolved by NS: %s\n",
							 string_name, ns_string);					
			got_answer=1;
			if(a+1==answer_count+auth_count+other_count){
				if(is_ipaddr(ns_string)){
				get_ipaddr(hostname, ns_string, res_string);
				}
				else{
					get_ipaddr2(ns_string, local_string);
					get_ipaddr(hostname, tmp_addr, res_string);
				}
			}
          
		}
		// CNAME record
		else if(htons(rr->type)==RECTYPE_CNAME) {
			char ns_string[255];
			int ns_len=from_dns_style(answerbuf,answer_ptr,ns_string);
			if(debug)
				printf("The name %s is also known as %s\n",
							 string_name, ns_string);								
			got_answer=1;
            //get_ipaddr(hostname, ns_string);
            strcpy(name, ns_string);
            get_ipaddr(ns_string, nameserver, res_string);
            return 1;
		}
		// PTR record
		else if(htons(rr->type)==RECTYPE_PTR) {
			char ns_string[255];
			int ns_len=from_dns_style(answerbuf,answer_ptr,ns_string);
			printf("%s domain name pointer %s\n",
						 string_name, ns_string);								
			got_answer=1;
            return 1;
		}
		// SOA record
		else if(htons(rr->type)==RECTYPE_SOA) {
			if(debug)
				printf("Ignoring SOA record\n");
            char ns_string[255];
            int ns_len=from_dns_style(answerbuf, answer_ptr, ns_string);
            printf("%s\n%s\n", string_name, ns_string);

		}
		// AAAA record
		else if(htons(rr->type)==RECTYPE_AAAA)  {
			if(debug)
				printf("Ignoring IPv6 record\n");
		}
		else {
			if(debug)
				printf("got unknown record type %hu\n",htons(rr->type));
		} 

		answer_ptr+=htons(rr->datalen);
	}
	
	if(!got_answer) printf("Host %s not found.\n",hostname);
    return -1;
	
}
