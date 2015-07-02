#include<stdlib.h>
#include<stdio.h>
#include<fcntl.h>
#include<unistd.h>
#include<string.h>
#include<sys/stat.h>
#include<sys/mman.h>
#include<sys/types.h>
#include<sys/socket.h>
#include <openssl/sha.h>
#include<bencodetools/bencode.h>
#include<curl/curl.h>
#include<arpa/inet.h>
#include<netinet/in.h>

#include<sys/select.h>

#include"BitTorrent_client.h"
#include<errno.h>
#include<signal.h>
#include<sys/socket.h>
#ifndef FD_COPY
#define FD_COPY(f, t)   (void)(*(t)=*(f))
#endif

// computed in main(). This is where we get our peers from.
char announce_url[255];

static fd_set readset, writeset;

enum {PIECE_EMPTY=0, PIECE_PENDING=1, PIECE_FINISHED=2, PIECE_SENDING=3} *piece_status;

#define BUFSIZE piece_length*2
struct peer_state *peers=0;

int debug=1;  //set this to zero if you don't want all the debugging messages 

char screenbuf[10000];

void print_bencode(struct bencode*);
void start_peers();
int Beginning;
int actualCount;
//int shutdown_peer(struct peer_state *);
int reconnect_to_peer(struct peer_state *);
void * connect_to_all_peers(struct bencode_list *peer_list);
//int handle_handshake_message(struct peer_state *);
int handle_message(struct peer_state *);
void sort_piece();
int send_handshake_message(struct peer_state *);
int recv_handshake_message(struct peer_state *);
int send_bitfield(struct peer_state*);
int send_have(int);
int send_unchoke(struct peer_state *);
int send_choke(struct peer_state *);
int send_piece(struct peer_state *, int, int , int);
// The SHA1 digest of the document we're downloading this time. 
// using a global means we can only ever download a single torrent in a single process. That's ok.
unsigned char digest[20];

// we generate a new random peer id every time we start
char peer_id[21]="-UICCS450-";
struct bencode_dict *torrent;
struct bencode *info;

int file_length=0;
int piece_length;

static int piece_count;
static int * piece_number;
static int * piece_sorted;
static int * piece_requested_number;

int account_piece(struct peer_state *, int);
void print_piece_number();

int active_peers() {//return the number of active peers
	struct peer_state *peer = peers;
	int count=0;
	while(peer) {
		if(peer->connected && !peer->choked)
			count++;
		peer = peer->next;
	}
	return count;
}

int choked_peers() {// return the number of choked peers
	struct peer_state *peer = peers;
	int count=0;
	while(peer) {
		if(peer->connected && peer->choked)
			count++;
		peer = peer->next;
	}
	return count;
}

int peer_connected(in_addr_t addr) {
    //confirm whether a peer with given IP is connected
    //if postive, return 1, otherwise return 0
	struct peer_state *peer = peers;
	while(peer) {
		if(peer->ip == addr && peer->connected==1) {
			return 1;
		}
		peer = peer->next;
	}	
	return 0;
}

void* draw_state() {
    //print out cur/mainrent state
		printf("\033[2J\033[1;1H");
		int pieces = file_length/piece_length+1;

		printf("%d byte file, %d byte pieces, %d pieces, %d active, %d choked\n",file_length,piece_length,file_length/piece_length+1,active_peers(),choked_peers());
		for(int i=0;i<pieces;i++) {
			if(i%80 == 0) printf("\n");

			switch(piece_status[i]) {
			case PIECE_EMPTY: printf("."); break;
			case PIECE_PENDING: printf("x"); break;
			case PIECE_FINISHED: printf("X"); break;
			default: printf("?");
			}
		}
		fflush(stdout);
}

int empty_blocks()
{
    //return number of empty pieces.
    int count = 0;

    for(int i=0;i<piece_count;i++)
        if(piece_status[i]==PIECE_EMPTY)
            count++;
    return count;
}

int missing_blocks() {
    // return number of unfinished pieces.
	int count=0;

	for(int i=0;i<file_length/piece_length+((file_length%piece_length)>0?1:0);i++) {
		if(piece_status[i]!=PIECE_FINISHED) {
			count++;
		}
	}
	return count;
}

/* so far, we're assuming that every peer actually have all pieces. That's not good! */
int next_piece(int previous_piece) {//NEED TO BE FIXed.
	//pthread_mutex_lock(&status_lock); 
	if(previous_piece!=-1)
		piece_status[previous_piece]=PIECE_FINISHED;
	
	draw_state();

	for(int i=0;i<(file_length/piece_length+1);i++) {
		if(piece_status[i]==PIECE_EMPTY) {
			if(debug)
				fprintf(stderr,"Next piece %d / %d\n",i,file_length/piece_length);
			piece_status[i]=PIECE_PENDING;			 
			return i;
		}
	}
    return -1;
}

/* Check whether a piece is kept by a peer */
int Check_piece(int piece_index, struct peer_state * pr)
{
    int fieldlen = piece_count/8 + 1;

    for(int i=0; i < fieldlen; i++){
        unsigned int tmp = pr->bitfield[i];
        for(int j = 7; j >= 0; j--)
            if(piece_index == (i*8+7-j))
                return ((tmp & ((1<<(j+1))-1))>>j)?1:0;
    }
}

/* Find out the rarest piece kept by a given peer */
int next_piece_for_peer(int previous_piece, struct peer_state * pr)
{

    if(previous_piece!=-1)
        piece_status[previous_piece] = PIECE_FINISHED;

    draw_state();

    for(int i = 0; i < piece_count; i++){
        if(piece_status[piece_sorted[i]] == PIECE_EMPTY){
            if(Check_piece(piece_sorted[i], pr)){
            //if(debug)
                //fprintf(stderr, "Next piece %d / %d\n", piece_sorted[i], file_length/piece_length);
                if(piece_status[piece_sorted[i]] == PIECE_PENDING){
                    if(piece_requested_number[piece_sorted[i]]<3){
                        piece_requested_number[piece_sorted[i]]++;
                        return piece_sorted[i];
                    }
                }
                else if(piece_status[piece_sorted[i]]==PIECE_EMPTY){
                    piece_requested_number[piece_sorted[i]]++;
                    piece_status[piece_sorted[i]]=PIECE_PENDING;
                    return piece_sorted[i];
                }
            }
            
        }
    }
	return -1;
}


int read_block(char ** ptr, int piece, int offset, int len){

    fprintf(stderr, "There is Read block\n");
    FILE * infile; 

    int accumulated_file_length = 0;
    int block_start = piece*piece_length + offset;

    struct bencode_list * files = (struct bencode_list *) ben_dict_get_by_str(info, "files");

    *ptr = (char *)malloc(len * sizeof(char)+1);
    int length = 0;
    //muti-file case
    if(files){
        for(int i = 0; i<files->n; i++){
            struct bencode * file = files->values[i];
            struct bencode_list * path = (struct bencode_list *)ben_dict_get_by_str(file, "path");

            //accumulate a total length so we know how many pieces there are
            int file_length = ((struct bencode_int *)ben_dict_get_by_str(file, "length"))->ll;

            printf("start %d len %d accum %d filelen %d\n", block_start, len, accumulated_file_length, file_length);
            
            //at least part of the block belongs in this file
            if((block_start >= accumulated_file_length) && ( block_start < accumulated_file_length+file_length)) {
                char filename[255];

                sprintf(filename, "%s/", ((struct bencode_str*)ben_dict_get_by_str(info, "name"))->s);
                for(int j=0; j<path->n;j++){
                    if(j<(path->n-1)){
                        sprintf(filename+strlen(filename), "%s/", ((struct bencode_str*)path->values[j])->s);
                    }
                    else
                        sprintf(filename+strlen(filename), "%s", ((struct bencode_str*)path->values[j])->s);
                }
                int infile = open(filename, O_RDONLY, 0777);
                if(infile == -1){
                    fprintf(stderr, "filename: %s\n", filename);
                    perror("Couldn't open file for reading");
                    return -1;
                }

                int offset_into_file = block_start - accumulated_file_length;
                int remaining_file_length = file_length - offset_into_file;
                lseek(infile, offset_into_file, SEEK_SET);
                
                if(remaining_file_length > len){
                 //   *ptr = (char *)malloc(len * sizeof(char )+1);
                    length += read(infile, * ptr, len);
                }
                else{
                    if(debug){
                        fprintf(stderr, "Uh-oh, Read crossing file boundaries... watch out!\n");
                        fprintf(stderr, "Len %d offset %d filelen %d remaining file len %d\n", len, offset_into_file, file_length, remaining_file_length);
                    }
                //    *ptr = (char *)malloc(len * sizeof(char)+1);

                    length += read(infile, * ptr, remaining_file_length);
                    close(infile);
                    
                    char * tmp;
                    tmp = (*ptr)+remaining_file_length;
                    length += read_block(&tmp, piece, offset+remaining_file_length, len-remaining_file_length);
                }
            }
            accumulated_file_length+=file_length;
        }


    }
    //single-file case
    else{
        
        struct bencode_str * name = (struct bencode_str*)ben_dict_get_by_str(info, "name");
        if(name){
            FILE * infile = fopen(name->s, "r+");
            file_length = ((struct bencode_int *)ben_dict_get_by_str(info, "length"))->ll;
            
            //read the data from the right spot in the file
            fseek(infile, piece*piece_length+offset, SEEK_SET);
         //   *ptr = (char *)malloc(len * sizeof(char)+1);
            length += fread(*ptr,1,len,infile);
            fclose(infile);
        }
        else{
            printf("No name?\n");
            return -1;
        }
    }

    return length;

}



/* This needs to be fixed to work properly for multi-file torrents. 
	 specifically, it needs to create the proper directory structure, rather than just concatenate directory and file names. 
 */
void write_block(char* data, int piece, int offset, int len, int acquire_lock) {
	FILE *outfile;


	int accumulated_file_length = 0;
	int block_start = piece*piece_length+offset;

	struct bencode_list* files = (struct bencode_list*)ben_dict_get_by_str(info,"files");
	// multi-file case
	if(files) {
		for(int i=0;i<files->n;i++) {
			struct bencode* file = files->values[i];
			struct bencode_list* path = (struct bencode_list*)ben_dict_get_by_str(file,"path");
			//			printf("Filename %s/%s\n",((struct bencode_str*)ben_dict_get_by_str(info,"name"))->s,((struct bencode_str*)path->values[0])->s);
			// accumulate a total length so we know how many pieces there are 
			int file_length=((struct bencode_int*)ben_dict_get_by_str(file,"length"))->ll; 

			printf("start %d len %d accum %d filelen %d\n",block_start,len,accumulated_file_length,file_length);
			fflush(stdout);
			// at least part of the block belongs in this file
			if((block_start >= accumulated_file_length) && (block_start < accumulated_file_length+file_length)) {
				char filename[255];
				
				mkdir(((struct bencode_str*)ben_dict_get_by_str(info,"name"))->s,0777);
				chmod(((struct bencode_str*)ben_dict_get_by_str(info,"name"))->s,07777);
				
				sprintf(filename,"%s/",((struct bencode_str*)ben_dict_get_by_str(info,"name"))->s);
				for(int j=0;j<path->n;j++) {					
					if(j<(path->n-1)) {
						sprintf(filename+strlen(filename),"%s/",((struct bencode_str*)path->values[j])->s);
						mkdir(filename,0777);
						chmod(filename,07777);
					}
					else
						sprintf(filename+strlen(filename),"%s",((struct bencode_str*)path->values[j])->s);
				}	
				
				int outfile = open(filename,O_RDWR|O_CREAT,0777);
				if(outfile == -1) {
					fprintf(stderr,"filename: %s\n",filename);
					perror("Couldn't open file for writing");
					exit(1);
				}
				
				int offset_into_file = block_start - accumulated_file_length;
				int remaining_file_length = file_length - offset_into_file;
				lseek(outfile,offset_into_file,SEEK_SET);

				if(remaining_file_length > len) {
					write(outfile,data,len);
					close(outfile);
					goto cleanup;
				}
				else {
					if(debug) {
						fprintf(stderr,"Uh-oh, write crossing file boundaries... watch out!\n");
						fprintf(stderr,"Len %d offset %d filelen %d remaining file len %d\n",len,offset_into_file,file_length,remaining_file_length);
						fflush(stdout);
					}

					write(outfile,data,remaining_file_length);
					close(outfile);
					write_block(data+remaining_file_length,piece,offset+remaining_file_length,len-remaining_file_length,0);
					goto cleanup;
				}

			}
			accumulated_file_length+=file_length;
		}
	}
	// single-file case
	else {

		struct bencode_str* name = (struct bencode_str*)ben_dict_get_by_str(info,"name");
		if(name) {
			FILE *outfile = fopen(name->s,"r+");
			file_length = ((struct bencode_int*)ben_dict_get_by_str(info,"length"))->ll;			

			// write the data to the right spot in the file
			fseek(outfile,piece*piece_length+offset,SEEK_SET);
			fwrite(data,1,len,outfile);
			fclose(outfile);
	
		}
		else {
			printf("No name?\n");
			exit(1);
		}
	}
	
 cleanup:
	if(acquire_lock);
}

// Wait for peer to send us another full message, then return the length of the new message.
int receive_message(struct peer_state* peer) {
	while(peer->count<4 || ntohl(((int*)peer->incoming)[0])+4 > peer->count) {
		int newbytes=recv(peer->socket,peer->incoming+peer->count,BUFSIZE-peer->count,0);
		if(newbytes == 0) {			
			fprintf(stderr,"Connection was closed by peer, count was %d, msg size %d\n",peer->count,ntohl(((int*)peer->incoming)[0]));
            //reconnect_to_peer(peer);
            FD_CLR(peer->socket, &readset);
            FD_CLR(peer->socket, &writeset);
            close(peer->socket);
			return 0;
		}
		else if(newbytes < 0) {
			perror("Problem when receiving more bytes, closing socket.");
            //reconnect_to_peer(peer);
            return 0;
			close(peer->socket);
			peer->connected = 0;	
    
		}
		peer->count+=newbytes;
	}		 
	return ntohl(((int*)peer->incoming)[0]);
}

// Drop the most recent message from the buffer. 
void drop_message(struct peer_state* peer) {
	int msglen = ntohl(((int*)peer->incoming)[0]); // size of length prefix is not part of the length
	if(peer->count<msglen+4) {
		fprintf(stderr,"Trying to drop %d bytes, we have %d!\n",msglen+4,peer->count);
		peer->connected=0;
		exit(1);
	}
	peer->count -= msglen+4; // size of length prefix is not part of the length
	if(peer->count) {
		memmove(peer->incoming,peer->incoming+msglen+4,peer->count);
	}
 }

 void request_block(struct peer_state* peer, int piece, int offset) {	

	 /* requests have the following format */
	 struct {
		 int len;
		 char id;
		 int index;
		 int begin;
		 int length;
	 } __attribute__((packed)) request;

	 request.len=htonl(13);
	 request.id=6;	
	 request.index=htonl(piece);
	 request.begin=htonl(offset);
	 request.length=htonl(1<<14);						

	 // the last block is likely to be of non-standard size
	 int maxlen = file_length - (piece*piece_length+offset);
	 if(maxlen < (1<<14))
		 request.length = htonl(maxlen);

	 // no point in sending anything if we got choked. We'll restart on unchoke.
	 // WARNING: not handling the case where we get choked in the middle of a piece! Does this happen?
	 if(!peer->choked) {
		 send(peer->socket,&request,sizeof(request),0);		
	 }
	 else 
		 fprintf(stderr,"Not sending, choked!\n");
 }


void send_interested(struct peer_state* peer) {
	struct {
		int len;
		char id;
	} __attribute__((packed)) msg;
	msg.len = htonl(1);
	msg.id = 2;

	send(peer->socket,&msg,sizeof(msg),0);
}



/* handle_announcement reads an announcement document to find some peers to download from.
	 start a new tread for each peer.
 */
//NEED TO BE FIXED
void handle_announcement(char *ptr, size_t size) {
	struct bencode* anno = ben_decode(ptr,size);

	printf("Torrent has %lld seeds and %lld downloading peers. \n",
				 ((struct bencode_int*)ben_dict_get_by_str(anno,"complete"))->ll,
				 ((struct bencode_int*)ben_dict_get_by_str(anno,"incomplete"))->ll);
		 
	struct bencode_list *peers = (struct bencode_list*)ben_dict_get_by_str(anno,"peers");

    //What is new

    connect_to_all_peers(peers);

}

/* contact the tracker to get announcement, call handle_announcement on the result */
void start_peers() {
//	pthread_mutex_lock(&anno_lock);//NEED TO BE FIXED
	/* now download the announcement document using libcurl. 
		 because of the way curl does things, it's easiest to just throw the entire document into a file first, 
		 and then just read the file. the alternative would be to buffer up all the data in memory using a
		 custom callback function. Let's stick with the KISS principle. 
	 */
	CURL *curl;
	CURLcode res;

	curl = curl_easy_init();
	if(curl) {
		curl_easy_setopt(curl, CURLOPT_URL, announce_url);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, 1);
		curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
		curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 1);

		FILE *anno = fopen("/tmp/anno.tmp","w+");
		if(!anno) {
			perror("couldn't create temporary file\n");
		}

		int attempts=0;
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, anno); 
		while((res = curl_easy_perform(curl)) !=CURLE_OK && 
					attempts < 5) {
			fprintf(stderr, "curl_easy_perform() failed: %s\n",
							curl_easy_strerror(res));
			attempts++;
		}
		fclose(anno);

		if (attempts<5) {
			struct stat anno_stat;
			if(stat("/tmp/anno.tmp",&anno_stat)) {
				perror("couldn't stat /tmp/anno.tmp");
				exit(1);
			}
			// the announcement document is in /tmp/anno.tmp. 
			// so map that into memory, then call handle_announcement on the returned pointner
			handle_announcement(mmap(0,anno_stat.st_size,PROT_READ,MAP_SHARED,open("/tmp/anno.tmp",O_RDONLY),0),anno_stat.st_size);
		}
		curl_easy_cleanup(curl);
	}
}

int main(int argc, char** argv) {
	if(argc<2) {
		fprintf(stderr,"Usage: ./BitTorrent_client <torrent file>\n");
		exit(1);
	}

	setvbuf(stdout,screenbuf,_IOFBF,10000);
		
	// create a global peer_id for this session. Every peer_id should include -CS450-.
	for(int i=strlen(peer_id);i<20;i++)
		peer_id[i]='0'+random()%('Z'-'0'); // random numbers/letters between 0 and Z
	
	// make sure the torrent file exists
	struct stat file_stat;
	if(stat(argv[1],&file_stat)) {
		perror("Error opening file.");
		exit(1);
	}

	// map .torrent file into memory, and parse contents
	int fd = open(argv[1],O_RDONLY);
	char *buf = mmap(0,file_stat.st_size,PROT_READ,MAP_SHARED,fd,0);
	if(buf==(void*)-1) {
		perror("couldn't mmap file");
		exit(1);
	}		 
	size_t off = 0;
	int error = 0;
	torrent = (struct bencode_dict*)ben_decode2(buf,file_stat.st_size,&off,&error);
	if(!torrent) {
		printf("Got error %d, perhaps a malformed torrent file?\n",error);
		exit(1);
	}

	// pull out the .info part, which has stuff about the file we're downloading
	info = (struct bencode*)ben_dict_get_by_str((struct bencode*)torrent,"info");
	
	struct bencode_list* files = (struct bencode_list*)ben_dict_get_by_str(info,"files");
	// multi-file case
	if(files) {
		for(int i=0;i<files->n;i++) {
			struct bencode* file = files->values[i];
			struct bencode_list* path = (struct bencode_list*)ben_dict_get_by_str(file,"path");
			printf("Filename %s/%s\n",((struct bencode_str*)ben_dict_get_by_str(info,"name"))->s,((struct bencode_str*)path->values[0])->s);

			// accumulate a total length so we know how many pieces there are 
			file_length+=((struct bencode_int*)ben_dict_get_by_str(file,"length"))->ll; 
		}
	}
	// single-file case
	else {
		struct bencode_str* name = (struct bencode_str*)ben_dict_get_by_str(info,"name");
		if(name) {
			file_length = ((struct bencode_int*)ben_dict_get_by_str(info,"length"))->ll;			
		}
	}
	fflush(stdout);
	piece_length = ((struct bencode_int*)ben_dict_get_by_str(info,"piece length"))->ll;

    //Initialize the array for pieces recording.
    piece_count = file_length/piece_length;
    if(file_length%piece_length!=0)
        piece_count++;
    piece_number = (int *)malloc(piece_count*sizeof(int));
    piece_sorted = (int *)malloc(piece_count*sizeof(int));
    piece_requested_number = (int *)malloc(piece_count*sizeof(int));
    for(int i = 0; i<piece_count; i++){
        piece_sorted[i] = i;
        piece_number[i] = 0;
        piece_requested_number[i] = 0;
    }

	// create our output file, and set up a piece_status array, and a couple of pthread sync. variables
	piece_status = calloc(1,sizeof(int)*(int)(file_length/piece_length+1)); //start with an empty bitfield
	/* compute the message digest and info_hash from the "info" field in the torrent */
	size_t len;
	char info_hash[100];  
	char* encoded = ben_encode(&len,(struct bencode*)info);
	SHA1(encoded,len,digest); // digest is a global that holds the raw 20 bytes
	
	// info_hash is a stringified version of the digest, for use in the announce URL
	memset(info_hash,0,100);
	for(int i=0;i<20;i++)
		sprintf(info_hash+3*i,"%%%02x",digest[i]);
		 

	// compile a suitable announce URL for our document
	sprintf(announce_url,"%s?info_hash=%s&peer_id=%s&port=6881&left=%d",((struct bencode_str*)ben_dict_get_by_str((struct bencode*)torrent,"announce"))->s,info_hash,peer_id,file_length);
	printf("Announce URL: %s\n",announce_url);
	fflush(stdout);


    struct sigaction sa;
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;
    if(sigemptyset(&sa.sa_mask)==-1 ||
            sigaction(SIGPIPE, &sa, 0) == -1){
        perror("Failed to ignore SIGPIPE; sigaction");
        exit(EXIT_FAILURE);
    }
	start_peers();
}


void * connect_to_all_peers(struct bencode_list *peer_list) {
    struct peer_addr * peerlist;

    fprintf(stderr, "There is the beginning of Connect_to_all_peers\n");
    if(peer_list->type == BENCODE_STR) {
        // handle the binary case
        fprintf(stderr, "Got binary list of peers\n");

        // the "string" in peers is really a list of peer_addr structes, so we'll just cast it as
        // such
        
        peerlist = (struct peer_addr *)((struct bencode_str *)peer_list)->s;

        for(int i=0; i<((struct bencode_str*)peer_list)->len/6;i++){
            struct in_addr a;
            a.s_addr = peerlist[i].addr;
            fprintf(stderr,"Found peer %s:%d\n", inet_ntoa(a), ntohs(peerlist[i].port));
        }
    }
    
    else {
        // handle the bencoded case

        fprintf(stderr,"Got bencoded list of peers\n");
        peerlist = (struct peer_addr *)malloc(sizeof(struct peer_addr)*peer_list->n);
        for(int i=0; i<peer_list->n; i++){
            struct bencode * peer = peer_list->values[i];
            char * address = ((struct bencode_str *)ben_dict_get_by_str(peer, "ip"))->s;
            unsigned short port = ((struct bencode_int *)ben_dict_get_by_str(peer, "port"))->ll;

            peerlist[i].addr = inet_addr(address);
            peerlist[i].port = htons(port);
        }
    }
    

    fprintf(stderr, "Starting to connect all peers\n");
    struct peer_addr * peeraddr;
    int s, res;
    struct sockaddr_in addr;
    struct timeval tv;
    struct peer_state * peer;
    int newbytes;

    // initializing data structure for select all
    int num_active_peer = 0;
    //static fd_set readset;
    FD_ZERO(&readset);
    //static fd_set writeset;
    FD_ZERO(&writeset);

    //Establish connection to all peers.
    for(int i=0; i<((struct bencode_str *)peer_list)->len/6; i++){
        peeraddr = peerlist+i;

        s = socket(AF_INET, SOCK_STREAM, 0);
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = peeraddr->addr;
        addr.sin_port = peeraddr->port;

        if(0>fcntl(s, F_SETFL, fcntl(s, F_GETFL, 0)|O_NONBLOCK)){
            fprintf(stderr, "fcntl failed\n");
            continue;
        }

        fprintf(stderr, "Connecting to %s\n", inet_ntoa(addr.sin_addr));
        // after 60 seconds of nothing, we probably should poke the peer to see if we can wake them
        // up

     /*   tv.tv_sec = 10;
        tv.tv_usec = 0;
        if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof tv)){
            perror("setsockopt");
            continue;
        }

        struct timeval tv1;
        tv1.tv_sec = 1;
        tv1.tv_usec = 0;
        if (setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv1, sizeof tv1)){
            perror("setsockopt2");
        }*/

        //fprintf(stderr,"SETTING Finished\n");
        res = connect(s, (struct sockaddr *)&addr, sizeof(addr));
        if(res == -1){
            fprintf(stderr, "Couldn't connect\n");
            fflush(stderr);
            perror("Error while connecting");
           // continue;
        }

        //fprintf(stderr,"Connected to %s\n", inet_ntoa(addr.sin_addr));

        FD_SET(s, &readset);
        FD_SET(s, &writeset);

        //register the peer in our list of peers
        peer = calloc(1, sizeof(struct peer_state));
        peer->socket = s;
        peer->ip = peeraddr->addr;
        peer->port = peeraddr->port;
        peer->next = peers;
        peer->connected = 0;
        peer->choked = 1;
        peer->requested_piece = -1;
        peer->incoming = malloc(BUFSIZE);
        peer->bitfield = calloc(1, file_length/piece_length/8+1);//Start with an empty bitfield.
        peer->send_handshake = 0;
        peer->recv_handshake = 0;
        peer->empty_count = 0;
        peer->tit_for_tat_count = 0;
        //The number of bytes in each pieces
        peers=peer;
        num_active_peer += 1;

    } //end for to establish connection

    fprintf(stderr, "Connection finished\n");

    fprintf(stderr, "************We have peers:*************\n");
    for(peer = peers; peer!=NULL;peer = peer->next){

        struct sockaddr_in addr;
        addr.sin_addr.s_addr = peer->ip;
        fprintf(stderr, "Sending handshake message to %s\n", inet_ntoa(addr.sin_addr));
    }
    fprintf(stderr,"***************************************\n\n");

    Beginning = 1;
    actualCount = 0;
    int isFinished = 0;

    int result;
    while(isFinished!=1)
    {
        fd_set rdyset, wdyset;
        FD_COPY(&readset, &rdyset);
        FD_COPY(&writeset, &wdyset);
        result = select(FD_SETSIZE, &rdyset, &wdyset, NULL, &tv);
        if(result < 0){
            perror("Select error:");
            exit (1);
        }
        if(result == 0)
            continue;
        for(peer = peers, s = 0; peer!=NULL; peer = peer->next)
        {
            //if(s==0)
               // fprintf(stderr, "s = %d", s);
            //fprintf(stderr, "Shaking\n");
            //handle_handshake_message(peer);
            if(FD_ISSET(peer->socket, &rdyset)){

                s=1;

                addr.sin_addr.s_addr = peer->ip;
    
                fprintf(stderr, "Now it's working at %s\n", inet_ntoa(addr.sin_addr));
                //actualCount++;
                if(peer->recv_handshake == 0)
                {
                    fprintf(stderr, "In rece_handshake");
                    recv_handshake_message(peer);
                }
                else{
                    fprintf(stderr, "\nhere is handle_message()\n");
                    handle_message(peer);
                }
                // there is still come pieces not fishied
                if(missing_blocks()>0){
                    fprintf(stderr, "\n%d active peers, %d missing blocks, %d empty blocks\n", active_peers(), missing_blocks(), empty_blocks());

                    if(active_peers()==0 && missing_blocks()>0){
                        printf("Ran out of active peers, reconnecting.\n");
                       //start_peers();
                       continue;
                    }
                }
                
                else{
                    isFinished = 1;
                    break;
                }
            }
            if(FD_ISSET(peer->socket, &wdyset)){
                s=1;
                if(peer->send_handshake == 0&&peer->connected == 0 && peer->recv_handshake ==0){
                    fprintf(stderr, "\nhere is FD_SET for writing\n");
                    send_handshake_message(peer);}
            
                else{
                   //send_bitfield(peer);
                }
            }
            if(!Beginning&&(actualCount<3))
            {
                s=1;
                if(peer->empty_count>=50){
                    fprintf(stderr, "\nhere is reconnection with start_peers()\n");
                    for(int i = 0; i<piece_count;i++)
                        if(piece_status[i] == PIECE_PENDING)
                            piece_status[i] = PIECE_EMPTY;
                    struct peer_state *ptr=peers;;
                    while(ptr!=NULL){
                        struct peer_state * tmp = ptr->next;
                        shutdown(ptr->socket, 2);
                        free(ptr->bitfield);
                        free(ptr->incoming);
                        free(ptr);
                        ptr = tmp;
                    }
                    peers = NULL;
                    start_peers();
                    isFinished = 1;
                    break;
                }
            }
        }//end for
        actualCount = 0;
    }//end while
    fprintf(stderr, "End While loop");
}

int send_handshake_message(struct peer_state * peer){
    // Send the handshake message
    // the handshake message:
    // <pstrlen><pstr><reserved><info_hash><peer_id>
    char protocol[] = "BitTorrent protocol";
    int res;
    unsigned char pstrlen = strlen(protocol);// not sure if this should be with or without terminator
    
    unsigned char buf[pstrlen+49];
    buf[0] = pstrlen;
    memcpy(buf+1, protocol, pstrlen);
    memcpy(buf+1+pstrlen+8, digest, 20);
    memcpy(buf+1+pstrlen+8+20, peer_id, 20);

    fprintf(stderr, "Sending the handshake message\n");
    fprintf(stderr,"socket = %d\n", peer->socket);
    res = send(peer->socket, buf, sizeof(buf), 0);
    peer->send_handshake =1;
    fprintf(stderr, "res = %d\nEnd Sending the handshake message\n", res);
    //peer->connected = 1;    
    
    // Receive the handshake message. This is different from all other messages, making things
    // ugly.
}

int recv_handshake_message(struct peer_state * peer)
{
   
    errno = 0;
    while(peer->count < 4 || peer->count < peer->incoming[0]+49){// ?why 49? no initialization for peer->incoming
        fprintf(stderr, "Receiving the handshake message.\n");
        int newbytes = recv(peer->socket, peer->incoming+peer->count, BUFSIZE-peer->count, 0);
        
        fprintf(stderr, "newbytes = %d\n", newbytes);
        if(newbytes == -1)
        {
            peer->connected = 0;
            perror("Newbytes = -1:");
            fprintf(stderr, "errno = %d\n", errno);
            if(errno == 111 || errno == 110)
               // goto shutdown;
               reconnect_to_peer(peer);
            else
                return -1;
        }
        else if(newbytes == 0){
            perror("Recieving handshake");
            //goto shutdown;
            reconnect_to_peer(peer);
        }
        //getchar();
        peer->count+=newbytes;
        fprintf(stderr, "peer->count = %d\n", peer->count);
    }

    
    
    if(memcmp(peer->incoming+peer->incoming[0]+8+20, "-UICCS450-", strlen("-UICCS450-"))==0){
        fprintf(stderr, "Caught a CS450 peer, shutdown.\n");
        goto shutdown;
    }
    
    
    //forget handshake packet
    if(debug)
        printf("handshake message is %d bytes\n", peer->count);
    

    peer->connected = 1;
    peer->recv_handshake = 1;
    peer->count -= peer->incoming[0]+49;
    if(peer->count)
        memmove(peer->incoming, peer->incoming+peer->incoming[0]+49, peer->count);

    return 0;
shutdown:
    fprintf(stderr, "Shuting down one peer\n");
    peer->connected = 0;
    //peer->send_handshake = 0;
    peer->choked = 1;
    if(peer->requested_piece>=0){
        if(piece_status[peer->requested_piece]!=PIECE_FINISHED){
            if(piece_requested_number[peer->requested_piece] == 1){
                piece_status[peer->requested_piece]=PIECE_EMPTY;
                piece_requested_number[peer->requested_piece]--;
            }
            
            else
                piece_requested_number[peer->requested_piece]--;
        }
    }
    peer->requested_piece = -1;
    FD_CLR(peer->socket, &writeset);
    FD_CLR(peer->socket, &readset);
    close(peer->socket);
}


int handle_message(struct peer_state * peer){

    int newbytes = 0;

    int msglen = receive_message(peer);
    
    fflush(stdout);
    if(msglen==0){
        peer->empty_count++;
        return 0;
   /*     peer->connected = 0;
        FD_CLR(peer->socket, &readset);
        FD_CLR(peer->socket, &writeset);
        close(peer->socket);
        piece_status[peer->requested_piece]=PIECE_EMPTY;
        draw_state();
        fprintf(stderr, "In msglen == 0");*/
        //getchar();
    }
    peer->empty_count = 0;
    actualCount++;
    switch(peer->incoming[4]){
        // CHOKE
         case 0:{
            if(debug)
                fprintf(stderr, "Choke\n");
            peer->choked = 1;
            if(peer->requested_piece>=0){
                if(piece_status[peer->requested_piece]!=PIECE_FINISHED){
                    piece_requested_number[peer->requested_piece]--;
                    if(piece_requested_number[peer->requested_piece]==0)
                        piece_status[peer->requested_piece]=PIECE_EMPTY;
                }
            }
            peer->requested_piece = -1;
            break;
        }
                
        //UNCHOKE
        case 1:{
            if(debug)
                fprintf(stderr, "Unchoke\n");
            peer->choked = 0;
            
            // grab a new piece - WARNING: this assumes that you don't get
            // choked mid-piece;
            peer->requested_piece = next_piece_for_peer(-1, peer);
            //peer->requested_piece = next_piece(-1);
            request_block(peer, peer->requested_piece, 0);
            break;
        }

        //INTERESTED
        case 2:{
            fprintf(stderr, "HERE IS AN INTERESTED MESSAGE!");
            //getchar();
            send_unchoke(peer);
            peer->choked = 0;
            break;
        }

        //NOT INTERESTED
        case 3:{
            fprintf(stderr, "HERE IS AN NOT INTERESTED MESSAGES!");
            //getchar();
            send_choke(peer);
            peer->choked = 1;
            if(peer->requested_piece>=0){
                if(piece_status[peer->requested_piece]!=PIECE_FINISHED){
                    piece_requested_number[peer->requested_piece]--;
                    if(piece_requested_number[peer->requested_piece]==0)
                        piece_status[peer->requested_piece] = PIECE_EMPTY;
                }
            }
            peer->requested_piece = -1;
            break; 
        }

        // HAVE -- update the bitfield for this peer
        case 4:{
            int piece_index = ntohl(*((int *)&peer->incoming[5]));
            int bitfield_byte = piece_index/8;
            int bitfield_bit = piece_index%8;
            if(debug)
                fprintf(stderr, "HAVE %d\n", piece_index);
            //OR the appropriate mask byte with a byte with the appropriate
            //single bit set
            if(piece_index > piece_count)
                break;
            peer->bitfield[bitfield_byte]|=1<<bitfield_bit;
            for(int i = 0; i<piece_count; i++){
                if(piece_sorted[i]==piece_index){
                    piece_number[i]++;
                    break;
                }
            }
            sort_piece();
            if(piece_status[piece_index] != PIECE_FINISHED)
            {
                if(peer->choked == 1)
                    send_interested(peer);
                else{
                    if(peer->requested_piece == -1)
                        peer->requested_piece = next_piece_for_peer(-1, peer);
                        
                    request_block(peer, peer->requested_piece, 0);
                }
            }
            break;
        }


               
        //BITFIELD -- set the bitfield for this peer
        case 5:{
            peer->choked = 0; // let's assume a bitfield means we're allowed to go...
            if(debug)
                printf("Bitfield of length %d\n", msglen-1);
            int fieldlen = msglen - 1;
            if(fieldlen != (file_length/piece_length/8+1)){
                fprintf(stderr, "Incorrect bitfield size, expected %d\n", file_length/piece_length/8+1);                 
                fprintf(stderr, "In bitfield");
          //      getchar();
              //  goto shutdown;
                reconnect_to_peer(peer);
            }
            memcpy(peer->bitfield, peer->incoming+5, fieldlen);

         /*   fprintf(stderr, "Bitfield:\n");
            for(int i=0; i < fieldlen; i++){
                unsigned int tmp = peer->bitfield[i];
                for(int j = 7; j >=0; j--)
                    fprintf(stderr, "%d", ((tmp & ((1<<(j+1))-1))>>j)?1:0);
                fprintf(stderr, " ");
            }
            fprintf(stderr, "\n");
*/
            account_piece(peer, fieldlen);
 //           print_piece_number();
/*
            for(int i =0; i<piece_count; i++){
                fprintf(stderr, "%d ", piece_sorted[i]);
                if((i+1)%8==0)
                    fprintf(stderr, "\n");
            }
            getchar();*/
            send_interested(peer);
            break;
        }
               
        // PIECE
        case 7: {
            Beginning = 0;
            int piece = ntohl(*((int*)&peer->incoming[5]));
            int offset = ntohl(*((int *)&peer->incoming[9]));
            int datalen = msglen - 9;

           // fprintf(stderr, "offset = %d, datalen = %d\n", offset, datalen);
           // getchar();
            
            fprintf(stderr, "Writting price %d, offset %d, ending at %d\n", piece, offset, piece*piece_length+offset+datalen);
            if(piece_status[piece]!=PIECE_FINISHED)
                write_block(peer->incoming+13, piece, offset, datalen,1);
            
            draw_state();
            offset+=datalen;
            if(offset==piece_length || (piece*piece_length+offset == file_length)) {
                if(debug)
                    fprintf(stderr, "Reached end of piece %d at offset %d\n", piece, offset);
                peer->requested_piece = next_piece_for_peer(piece, peer);
                //peer->requested_piece = next_piece(piece);
                if(peer->requested_piece != piece)
                    send_have(piece);
                offset = 0;
                
                if(peer->requested_piece == -1){
                    fprintf(stderr, "No more pieces to download!\n");
                    
                    int i;
                    // don't exit if some piece is still being downloaded
                    for( i=0; i<file_length/piece_length+1; i++)
                        if(piece_status[i]!=2){
                            //fprintf(stderr, "In piece");
                            //piece_status[i] = 2;
                            //getchar();
                            
                            peer->requested_piece = i;
                            piece_requested_number[i]++;
                            request_block(peer, peer->requested_piece, offset);
                            drop_message(peer);
                            return 0;
                            //goto shutdown;
                        }
                    //if(i == file_length/piece_length+1)
                    //    draw_state();
                    //    exit (1);
                }
                
            }
            
            request_block(peer, peer->requested_piece, offset);
            break;
        }
               
        //REQUEST
        case 6:{
            fprintf(stderr, "HERE IS A REQUEST");
            int index = ntohl(*((int*)&peer->incoming[5]));
            int begin = ntohl(*((int*)&peer->incoming[9]));
            int length = ntohl(*((int*)&peer->incoming[13]));
            fprintf(stderr, "index = %d, bigen = %d, length = %d\n",index, begin, length);
            if(piece_status[index]==PIECE_FINISHED){
                send_piece(peer, index, begin, length);
                peer->tit_for_tat_count--;
                if(peer->tit_for_tat_count<=-2)
                {
                    send_choke(peer);
                    peer->choked = 1;
                    if(peer->requested_piece>=0){
                        if(piece_status[peer->requested_piece]!=PIECE_FINISHED){
                            piece_requested_number[peer->requested_piece]--;
                            if(piece_requested_number[peer->requested_piece]==0)
                                piece_status[peer->requested_piece] = PIECE_EMPTY;
                        }
                    }
                    peer->requested_piece = -1;
                }
                else
                {
                    if(peer->requested_piece = -1)
                        peer->requested_piece = next_piece_for_peer(-1, peer);
                    request_block(peer, peer->requested_piece, 0);
                }
            }
            else
            {
                send_choke(peer);
                peer->choked = 1;
                if(peer->requested_piece>=0){
                    if(piece_status[peer->requested_piece]!=PIECE_FINISHED){
                        piece_requested_number[peer->requested_piece]--;
                        if(piece_requested_number[peer->requested_piece]==0)
                            piece_status[peer->requested_piece] = PIECE_EMPTY;
                    }
                }
                peer->requested_piece = -1;
            }
            //getchar();
            break;
        }
        case 20:{
            printf("Extended type is %d\n",peer->incoming[5]);
            struct bencode * extended = ben_decode(peer->incoming, msglen);
            print_bencode(extended);
            break;
        }
    }//end of switch, cases of peer's incoming
    drop_message(peer);
    return 0;
shutdown:
    fprintf(stderr, "Shutting down one peer.\n");
    peer->connected = 0;
    //peer->send_handshake = 0;
    peer->choked = 1;
    if(peer->requested_piece>=0){
        if(piece_status[peer->requested_piece]!=PIECE_FINISHED){
            piece_requested_number[peer->requested_piece]--;
            if(piece_requested_number[peer->requested_piece]==0)
                piece_status[peer->requested_piece] = PIECE_EMPTY;
        
        }
    }
    peer->requested_piece = -1;
    FD_CLR(peer->socket, &writeset);
    FD_CLR(peer->socket, &readset);
    close(peer->socket);
    return 0;
}

int account_piece(struct peer_state * pr, int count)
{
    unsigned int n, res;
    int index = 0;
    int k;
    for(int i = 0; i <= count; i++){
        n = pr->bitfield[i];

        for(int j = 7; j >=0; j--)
        {
            if((i*8)+(7-j)>=piece_count)
                goto END;
            index = (i*8)+(7-j);
          //  fprintf(stderr, "index = %d", index);
            res = ((n & ((1<<(j+1))-1))>>j)?1:0;
          //  fprintf(stderr, "n = %d", res);
          //  getchar();
            for(k = 0; k < piece_count; k++)
                if(piece_sorted[k]==index)
                    piece_number[k] += res;
        }
    }

END:
    sort_piece();
    return 0;
}

void print_piece_number()
{
    for(int i = 0; i < piece_count; i++)
    {
        fprintf(stderr, "%d", piece_number[i]);
        if((i+1)%8==0)
            fprintf(stderr," ");
    }
    fprintf(stderr, "\n");
}

void sort_piece()
{
    int i;
    int j;
    int k;
    int tmp;
    for(i = 0; i < piece_count; i++)
    {
        k = i;
        for(j = i+1; j < piece_count; j++)
        {
            if(piece_number[k]>piece_number[j])
                k = j;
        }
        if(k!=i){
            tmp = piece_number[k];
            piece_number[k] = piece_number[i];
            piece_number[i] = tmp;

            tmp = piece_sorted[k];
            piece_sorted[k] = piece_sorted[i];
            piece_sorted[i] = tmp;
        }
    }
}

int reconnect_to_peer(struct peer_state * peer)
{
    fprintf(stderr, "Shutdown and reconnect to peer\n");
    FD_CLR(peer->socket, &writeset);
    FD_CLR(peer->socket, &readset);
    close(peer->socket);
    int s;
    s = (AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = peer->ip;
    addr.sin_port = peer->port;

    if(0>fcntl(s, F_SETFL, fcntl(peer->socket, F_GETFL, 0)|O_NONBLOCK)){
        fprintf(stderr, "fcntl failed\n");
        return -1;
    }

    int res = connect(s, (struct sockaddr *)&addr, sizeof(addr));
    if(res = -1){
        fprintf(stderr, "Couldn't connect\n");
        fflush(stderr);
        perror("Error while reconnecting");
        return -1;
    }

    FD_SET(s,&readset);
    FD_SET(s,&writeset);

    peer->socket = s;
    peer->connected = 0;
    peer->choked = 1;
    if(peer->requested_piece>=0){
        if(piece_status[peer->requested_piece]!=PIECE_FINISHED){
            piece_requested_number[peer->requested_piece]--;
            if(piece_requested_number[peer->requested_piece]==0)
                piece_status[peer->requested_piece]=PIECE_EMPTY;
        }
    }
    peer->requested_piece = -1;
    peer->send_handshake = 0;
    peer->recv_handshake = 0;
}

int send_bitfield(struct peer_state * peer)
{
    fprintf(stderr, "Beginning");
    int length = piece_count/8;
    int num = 128;
    if(piece_count%8!=0)
        length++;
    char *buf = (char *)malloc((length+1)*sizeof(char));
    buf[0] = 5;
    for(int i = 0; i < length;i++)
    {
        for(int j = 7; j >= 0; j--)
        {
            if((i*8)+(7-j)>=piece_count)
                break;
            if(piece_status[(i*8)+(7-j)]==1)
                buf[i] = buf[i]|num;
            num = num/2;
        }
        num = 128;
    }
    send(peer->socket, &buf, length+1, 0);

    fprintf(stderr, "Ending");

}

int send_have(int index)
{
    fprintf(stderr, "Sending HAVE");
    struct {
        int len;
        char id;
        int index;
    }__attribute__((packed)) have;

    have.len = htonl(5);
    have.id = 4;
    have.index = htonl(index);

    struct peer_state * pr;
    for(pr = peers; pr!=NULL; pr = pr->next)
        if(pr->choked!=0)
            send(pr->socket, &have, sizeof(have), 0);

    return 1;

    
}

int send_unchoke(struct peer_state * peer)
{
    fprintf(stderr, "Sending Unchoke");
    struct{
        int len;
        char id;
    }__attribute__((packed)) unchoke;

    unchoke.len = htonl(1);
    unchoke.id = 1;

    send(peer->socket, &unchoke, sizeof(unchoke), 0);
    return 1;
}

int send_choke(struct peer_state * peer)
{
    fprintf(stderr, "Sending Choke");
    struct{
        int len;
        char id;
    }__attribute__((packed)) choke;

    choke.len = htonl(1);
    choke.id = 0;

    send(peer->socket, &choke, sizeof(choke), 0);
    return 1;
}

int send_piece(struct peer_state * peer, int index, int begin, int length)
{

    fprintf(stderr, "Sending piece");
    char * buf;
    int len;
    len = read_block(&buf, index, begin, length);
    fprintf(stderr, "length = %d, len = %d\n", length, len);
    if(len < 0)
        return 0;
    struct{
        int len;
        char id;
        int index;
        int begin;
    }__attribute__((packed)) piece;

    piece.len = htonl(13);
    piece.id = 7;
    piece.begin = begin;

    char * buffer;

    buffer = (char*)malloc(sizeof(char)*len+sizeof(piece));

    memcpy(buffer, &piece, sizeof(piece));
    memcpy(buffer+sizeof(piece), buf, sizeof(char)*len);

    send(peer->socket, buf, sizeof(char)*len+sizeof(piece), 0);
    fprintf(stderr, "Sending %d\n", sizeof(char)*len+sizeof(piece));
    //getchar();
    return 1;
    
}
