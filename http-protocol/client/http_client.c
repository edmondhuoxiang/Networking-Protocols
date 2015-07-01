#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

static char hostname[BUFSIZ];
static char pathname[BUFSIZ];
static char filename[BUFSIZ];
static char cookie[BUFSIZ];


int get_url(char * url)
{
	//Initialize the names of Host, Path and File
    memset(hostname, '\0', BUFSIZ);
    memset(pathname, '\0', BUFSIZ);
    memset(filename, '\0', BUFSIZ);

    char * tmp_pt1, * tmp_pt2, * tmp_pt3;

	//get hostname, such as www.google.com
	if((tmp_pt1 = strstr(url, "http://")) == NULL)
        tmp_pt1 = url;
	else
		tmp_pt1 = url + strlen("http://");

	if((tmp_pt2 = strstr(tmp_pt1, "/"))==NULL){
		strcpy(hostname, tmp_pt1);
	}
	else{
		strncpy(hostname, tmp_pt1, (int)(tmp_pt2 - tmp_pt1));
	}

	//get pathname, such as "/intl/en_ALL/
	for (tmp_pt2 = tmp_pt1; *tmp_pt2 != '/' && *tmp_pt2 != '\0'; tmp_pt2++);

	if ((int)(tmp_pt2 - tmp_pt1) == strlen(tmp_pt1)){
		strcpy(pathname, "/");
	}
	else{
		strcpy(pathname, tmp_pt2);
    }
	
	//get filename, default name is "index.html"
	tmp_pt3 = tmp_pt2 + strlen(tmp_pt2)-1;
	while(*tmp_pt3 != '/' && tmp_pt3 >= tmp_pt2)
		tmp_pt3--;
	tmp_pt3++;
	if(*tmp_pt3 == '\0')
		strcpy(filename, "index.html");
	else
        strcpy(filename, tmp_pt3);

	return 1;
}




int main(int argc, char ** argv)
{
	//Judge the number of parameter
	if (argc < 2){
		perror("Usage: Please input a URL.\n");
		exit (0);
	}

	//Process URL to get hostname, pathname and filename
	printf("Processing URL...");
	get_url(argv[1]);
	printf("\t\tOK\n");

	//Initialize and Create sockct
	printf("Initializing and creating socket...");
	int s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s < 0){
		printf("\tFAILED\n");
		perror("Cannot create a socket.\n");
		exit (0);
	}
	else
		printf("\tOK\n");

	//Get IP address by hostname
	printf("Getting IP address...");
	struct hostent * ipHost;
	ipHost = gethostbyname(hostname);
    if(ipHost == NULL){
		printf("\tFAILED\n");
        perror("Cannot get IP address\n");
        exit (1);
    }
	else
		printf("\tOK\n");


    printf("HOST : %s\nPATH : %s\nFILE : %s\n", hostname, pathname, filename);
	printf("The IPv4 address is %s\n", inet_ntoa(*((struct in_addr*)ipHost->h_addr_list[0])));

	//Set parameters for struct sockadd_in
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(80);
	addr.sin_addr.s_addr = inet_addr(inet_ntoa(*((struct in_addr*)ipHost->h_addr_list[0])));

	//Initialize and set variable header to send to host
	char header[BUFSIZ] = "";
	strcat(header, "GET ");
	strcat(header, pathname);
	strcat(header, " HTTP/1.0\r\n");
	strcat(header, "HOST: ");
	strcat(header, hostname);
    strcat(header, "\r\nAccept: */*");
	strcat(header, "\r\nConnection: Close\r\n\r\n");
    printf("HEAD : \n%s", header);

	//Initialize and create connect to the host
	printf("Initializing and creating connect...");
	int res = connect(s, (struct sockaddr *) & addr, sizeof(addr));
	if (res < 0){
		printf("\tFIALED\n");
		perror("Cannot creat the connection.\n");
		exit(0);
	}
	else
		printf("\tOK\n");

	//Send request to host
	printf("Sending request...");
	send(s, header, strlen(header), 0);
	printf("\t\tOK\n");

	char  buffer[BUFSIZ];
    int result;
    char * offset = 0;
    FILE * fp;
    int flag = 0;
  
	//receive data and save into buffer
	printf("Receiving response...\n");
    result = recv(s, buffer, BUFSIZ, 0);
    buffer[result] = '\0';


    if(strstr(buffer, "200 OK") != NULL){//Page found
		printf("Saving data to File : %s...", filename);
        fp = fopen(filename, "w");
		do{
			offset = strstr(buffer, "\r\n\r\n");//Find body of page
            if(offset == NULL)
                offset = &buffer[0];
            else{
                offset = offset + 4;
                flag = 1;
            }
            if(flag)
                fwrite(offset, sizeof(char), buffer+result-offset, fp);//Save data into file
            memset(buffer, '\0', BUFSIZ);
        }while(result = recv(s, buffer, BUFSIZ, 0));
        fclose(fp);
		printf("\tOK\n");
    }
    else if(strstr(buffer, "404 Not Found") != NULL){
        perror("404 Not Found");
        close(s);
        exit(1);
    }
	else if(strstr(buffer, "302 Found") != NULL){
        perror("302 Found");
        close(s);
        exit (1);
    }
    else if((strstr(buffer, "302 Moved Temporarily") != NULL) || (strstr(buffer, "301 Moved Permanently") != NULL)){
		//Page was moved.
		//Get new location of the target page
        char * offset_head;
        while((offset_head = strstr(buffer, "Location")) == NULL)
            result = recv(s, buffer, BUFSIZ, 0);
        offset_head = offset_head + strlen("Location: ");
        offset = strstr(offset_head, "\r\n");

        //Find out whether need to add cookie to new request
        char * cookie_start,* cookie_end;
        char  cookie_buffer[BUFSIZ];
        memset(cookie, '\0', BUFSIZ);
        if((cookie_start = strstr(buffer, "Cookie: ")) != NULL){
            strcpy(cookie_buffer, buffer);
            cookie_start = strstr(cookie_buffer, "Cookie: ");
            cookie_start = cookie_start + strlen("Cookie: ");
            do{
                cookie_start = cookie_start+strlen("Cookie: ");
                if((cookie_end = strstr(cookie_start, ";")) == NULL){
                    cookie_end = strstr(cookie_start,"\r\n");
                    * cookie_end = '\0';
                    }
                else{
                    cookie_end++;
                    * cookie_end = '\0';
                }
                strcat(cookie, cookie_start);
                strcat(cookie, " ");
                cookie_start = cookie_end+1;
            }while((cookie_start = strstr(cookie_start, "Cookie: ")) != NULL);

        }
        cookie_end = cookie+strlen(cookie)-2;
        * cookie_end = '\0';
        *offset = '\0';

        printf("\n\n****New URL: %s****\n", offset_head);

		//Get new hostname, pathname and filename
		printf("Processing new URL...");
        get_url(offset_head);
		printf("\tOK\n");

		//Set new header for the second request
        memset(header, '\0', BUFSIZ);
        strcat(header, "GET ");
        strcat(header, pathname);
        strcat(header, " HTTP/1.1\r\n");
        strcat(header, "Accept: */*\r\n");
        strcat(header, "HOST: ");
        strcat(header, hostname);
        strcat(header, "\r\nConnection: Close\r\n");
        if(strlen(cookie)!=0){
            strcat(header, "Cookie: ");
            strcat(header, cookie);
            strcat(header, "\r\n\r\n");
        }
        else
            strcat(header, "\r\n");

		//Shut down old socket and start a new one.
        close(s);
		printf("Initializing and creating socket...");
        s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
        if(s < 0)
        {
			printf("\tFIALED\n");
            perror("Cannot create a socket.\n");
            exit (0);
        }
		else
			printf("\tOK\n");

		//Get new IP address by host
		printf("Getting IP address...");
        ipHost = gethostbyname(hostname);
        if(ipHost == NULL){
			printf("\tFAILED\n");
            perror("Cannot get IP address\n");
            exit (0);
        }
		else
			printf("\tOK\n");
       
		printf("HOST : %s\nPATH : %s\nFILE : %s\n", hostname, pathname, filename);
		printf("IPv4 address : %s\n", inet_ntoa(*((struct in_addr *)ipHost->h_addr_list[0])));
		printf("HEAD : \n%s", header);
		//Set new IP address
		addr.sin_addr.s_addr = inet_addr(inet_ntoa(*((struct in_addr*)ipHost->h_addr_list[0])));

		//Create new connect
		printf("Initializing and creating connect...");
        res = connect(s, (struct sockaddr *) & addr, sizeof(addr));
        if(res < 0){
			printf("\tFIALED\n");
            perror("Cannot create the connection\n");
            exit (0);
        }
		else
			printf("\tOK\n");

		//Send request and start to receive data
        memset(buffer, '\0', BUFSIZ);
        flag = 0;
		printf("Sending request...");
        send(s, header, strlen(header), 0);
		printf("\t\tOK\n");

		printf("Receiving respense...\n");
        result = recv(s, buffer, BUFSIZ, 0);
        buffer[result] = '\0';

		//In this version, if the second request doesn't get the right page,
		//report is as an error and exit.
        if(strstr(buffer, "200 OK\r\n") == NULL){
            perror("Movded Twice");
            exit (0);
        }
		printf("Saving data to FILE : %s...", filename);
        fp = fopen(filename, "w");
        do{
            offset = strstr(buffer, "\r\n\r\n");
            if(offset == NULL)
                offset = &buffer[0];
            else{
                offset = offset + 4;
				//There is a strange string in response...
                if(strstr(offset, "00004000\r\n\r\n")!=NULL){
                    offset = strstr(offset, "00004000\r\n\r\n");
                    offset = offset+strlen("00004000\r\n\r\n");
                }
                flag = 1;
            }
            if(flag)
                fwrite(offset, sizeof(char), buffer+result-offset, fp);
            memset(buffer, '\0', BUFSIZ);
        }while(result = recv(s, buffer, BUFSIZ, 0));
        fclose(fp);
		printf("\tOK\n");
    }
    else if(strstr(buffer, "403 Forbidden") != NULL){
        perror("403 Forbidden");
        close(s);
        exit (1);
    }
    else if(strstr(buffer, "400 Bad Request") != NULL){
        perror("400 Bad Request");
        close(s);
        exit (1);
    }
	close(s);

	return 1;

}
