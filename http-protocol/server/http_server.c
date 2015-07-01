//This is a mulit-thread version
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <errno.h>
#include <sys/stat.h>
#include <pthread.h>
#define MAX 10
pthread_t thread[MAX];
int thread_num = 0;
int status[MAX];
static char foldername[BUFSIZ];


int get_info(char * buffer, char * hostname, char *pathname, 
             char * filename, char * portnum, char * type){

    char * path_begin;
    char * tmp_pt; 
    char * tmp_pt2;

    memset(hostname, '\0', BUFSIZ);
    memset(pathname, '\0', BUFSIZ);
    memset(filename, '\0', BUFSIZ);
    memset(portnum, '\0', 32);
    memset(type, '\0', 16);

    if((path_begin = strstr(buffer, "GET "))==NULL){
        printf("Get page failed\n");
        return 0;
            }
    
    path_begin = path_begin + strlen("GET ");
    strcpy(pathname, path_begin);

    for(tmp_pt = pathname; *tmp_pt != '\0' && *tmp_pt != ' '; tmp_pt++);

    if(* tmp_pt == '\0'){
        printf("Get path failed\n");
        return 0;
    }
    else
        * tmp_pt = '\0';
    
    for(tmp_pt2 = tmp_pt; tmp_pt2 != pathname && *tmp_pt2 != '/'; tmp_pt2--);

    if(tmp_pt2 == tmp_pt-1){
        strcpy(filename, "index.html");
    }
    else{
        tmp_pt2++;
        strcpy(filename, tmp_pt2);
        * tmp_pt2 = '\0';
    }
    
    if((path_begin = strstr(buffer, "Host: "))==NULL){
        printf("GET page failed\n");
        return 1;
    }
    else{
        path_begin = path_begin + strlen("Host: ");
        
        for(tmp_pt = path_begin; *tmp_pt != '\0' && *tmp_pt != ':'; tmp_pt++);
        if(*tmp_pt == '\0'){
            printf("Error hostname or port\n");
            return 1;
        }
        for(tmp_pt2 = tmp_pt; *tmp_pt2 != '\0' && * tmp_pt2 != '\r'; tmp_pt2++);
        if(*tmp_pt2 == '\0'){
            printf("Error hostname or port\n");
            return 1;
        }
        * tmp_pt2 = '\0';
        strcpy(portnum, tmp_pt+1);
        * tmp_pt = '\0';
        strcpy(hostname, path_begin);
    }

    for(tmp_pt = filename; * tmp_pt != '\0' && * tmp_pt != '.'; tmp_pt++);
    if(*tmp_pt == '\0')
        strcpy(type, "html");
    else
        strcpy(type, tmp_pt+1);


    return 1;
}

void * process_request(void * argc_thread)
{
    int sock_thread;
    FILE * fp;
    char header[BUFSIZ];
    char buffer_tmp[BUFSIZ];
    int result;
    struct stat file_status;
	char buf[BUFSIZ];

    char hostname[BUFSIZ];
    char pathname[BUFSIZ];
    char filename[BUFSIZ];
    char type[16];
    char portnum[32];


    sock_thread =* (int *)(argc_thread);
    memset(buf, 0, BUFSIZ);
    int recv_count = recv(sock_thread, buf, BUFSIZ, 0);
    if(recv_count < 0){
        perror("Receive failed");
        exit (1);
    }
    printf("----------Request Begin----------\n");
    
    printf("%s", buf);
    
    printf("-----------Request End-----------\n\n\n\n");
    
    get_info(buf, hostname, pathname, filename, portnum, type);    
    printf("PATH : %s\n", pathname);
    printf("FILE : %s\n", filename);
    printf("FOLDER : %s\n", foldername);
    
    memset(buffer_tmp, '\0', BUFSIZ);
    memset(header, '\0', BUFSIZ);
    
    strcpy(buffer_tmp, foldername);
    strcat(buffer_tmp, pathname);
    strcat(buffer_tmp, filename);
    
    stat(buffer_tmp, &file_status);
    
    if((fp = fopen(buffer_tmp, "r")) == NULL){
        strcpy(header, "HTTP/1.0 404 Not Found\r\n");
        strcat(header, "Content-Type: text/html; Charset=UTF-8\r\n\r\n");
        send(sock_thread, header, strlen(header),0);
        shutdown(sock_thread, SHUT_RDWR);
        close(sock_thread);
        return 0;
    }
    strcpy(header, "HTTP/1.1 200 OK\r\n");
    strcat(header, "Accept-Ranges: bytes\r\n");
    strcat(header, "Content-Length: ");
    sprintf(buffer_tmp, "%lld", (unsigned long long)(file_status.st_size));
    strcat(header, buffer_tmp);
    strcat(header, "\r\nConnection: Keep Alive\r\n");
    strcat(header, "Content-Type: ");
    if(strcmp(type, "html")==0)
        strcat(header, "text/html\r\n");
    else if(strcmp(type, "txt")==0)
        strcat(header, "text/plain\r\n");
    else if(strcmp(type, "jpg")==0 || strcmp(type, "jpeg")==0)
        strcat(header, "image/jpeg\r\n");
    else if(strcmp(type, "gif")==0)
        strcat(header, "image/gif\r\n");
    else if(strcmp(type, "png")==0)
        strcat(header, "image/png\r\n");
    else if(strcmp(type, "pdf")==0)
        strcat(header, "application/pdf\r\n");
    else
        strcat(header, "text/html\r\n");
    strcat(header, "Content-Language: en\r\n");
    strcat(header, "Set-Cookie: ");
    strcat(header, "path=");
    strcat(header, pathname);
    strcat(header, "; domain=");
    strcat(header, hostname);
    strcat(header, ":");
    strcat(header, portnum);
    strcat(header, "\r\n\r\n");
    
    printf("HEAD:\n%s", header);
    send(sock_thread, header, strlen(header), 0);
    
    while((result = fread(header, sizeof(char), BUFSIZ, fp))!=0){
        send(sock_thread, header, result, 0);
    }
    
    shutdown(sock_thread, SHUT_RDWR);
    close(sock_thread);
    thread_num --;
}



int main(int argc, char ** argv){

    if (argc < 3){
        perror("Usage: Please input two parameters");
        exit (1);
    }

    strcpy(foldername, argv[2]);

    printf("Creating a socket: ...\t\t");
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if(server_sock < 0){
        perror("Creating socket failed\n");
        exit (1);
    }
    else
        printf("Ok\n");

    // allow fast reuse of ports
    int reuse_true = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &reuse_true, sizeof(reuse_true));//Set Socket optrion

    struct sockaddr_in addr; //internet socket address data structure;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(atoi(argv[1]));//btye order is significant
    addr.sin_addr.s_addr = INADDR_ANY;//listen to all interfaces

    printf("Creating a bind: ...\t\t");
    int res = bind(server_sock, (struct sockaddr *)&addr, sizeof(addr));
    if( res < 0){
        perror("Error binding to port");
        exit (1);
    }
    else
        printf("Ok\n");

    struct sockaddr_in remote_addr;
    unsigned int socklen = sizeof(remote_addr);


    int sock;

    int i= 0;
    for(i = 0; i < MAX; i++)
    {
        status[i] = 1;
    }

    while(1){
        //wait for a connection
        printf("Wating for a connection...\n");
        res = listen(server_sock, 0);
        if(res < 0){
            perror("Error listening for connection");
            exit (1);
        }
        
        sock = accept(server_sock, (struct sockaddr *)&remote_addr, &socklen);
        if(sock < 0){
            perror("Error accepting connection");
            exit (1);
        }

        if(thread_num < MAX){
            for(i = 0; i < MAX; i++)
                if(status[i])
                    break;
            status[i] = 1;
            pthread_create(&thread[i], NULL, process_request, (void *)&sock);
        }

        
    }

    
    shutdown(server_sock, SHUT_RDWR);
    return 1;
}
