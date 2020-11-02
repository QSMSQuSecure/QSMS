#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include "data.h"

void error(char *msg)
{
    perror(msg);
    return;
}

int main(int argc, char *argv[])
{
    int sockfd, portno, n;

    struct sockaddr_in serv_addr;
    struct hostent *server;

    buffer_t *buf;

    buf = (buffer_t*) malloc(sizeof(buffer_t));

    if (argc < 3) {
       fprintf(stderr,"usage %s hostname port\n", argv[0]);
       return 0;
    }
    portno = atoi(argv[2]);
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) 
        error("ERROR opening socket");
    server = gethostbyname(argv[1]);
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host\n");
        return 0;
    }
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, 
         (char *)&serv_addr.sin_addr.s_addr,
         server->h_length);
    serv_addr.sin_port = htons(portno);
    if (connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0) 
        error("ERROR connecting");
    printf("Please enter the message: ");
    bzero(buf->input,BUFFERSIZE);
    fgets(buf->input,BUFFERSIZE-1,stdin);
    n = write(sockfd,buf->input,BUFFERSIZE);
    if (n < 0) 
         error("ERROR writing to socket");
    bzero(buf->input,256);
    n = read(sockfd,buf->input,BUFFERSIZE-1);
    if (n < 0) 
         error("ERROR reading from socket");
    //printf("%s\n",buf->input);
    return 0;
}
