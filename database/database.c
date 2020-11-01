#include "data.c"
#include "database.h"

pub_t *readBuf(data_t *data, buffer_t buffer) {

   u_int16_t i;
   read_t r;
   write_t w;

   if (buffer.input[0] == 0x00) {

      for (i = 0; i < READSIZE; i++) r.read[i] = buffer.input[i + 1];
      return userRead(data, r);
   }

   else if (buffer.input[0] == 0x01) {

      for (i = 0; i < WRITESIZE; i++) w.write[i] = buffer.input[i + 1];
      return userWrite(data, w);
   }

   return NULL;
}

pub_t *userRead(data_t *data, read_t input) {



}

pub_t *userWrite(data_t *data, read_t input) {



}
  
void error(char *msg) {
   
   perror(msg);
   exit(1);
}

void dostuff (int sock) {
   
   int n;
   char buffer[BUFFERSIZE];

   bzero(buffer, BUFFERSIZE);
   n = read(sock, buffer, BUFFERSIZE - 1);
   if (n < 0) error("ERROR reading from socket");
   printf("Here is the message: %s\n",buffer);
   n = write(sock,"I got your message",18);
   if (n < 0) error("ERROR writing to socket");
}

int main(int argc, char *argv[]) {

   int sockfd, newsockfd, portno, clilen, pid;
   struct sockaddr_in serv_addr, cli_addr;

   if (argc < 2) {
      fprintf(stderr,"ERROR, no port provided\n");
      exit(1);
   }
   sockfd = socket(AF_INET, SOCK_STREAM, 0);
   if (sockfd < 0) error("ERROR opening socket");
   bzero((char *) &serv_addr, sizeof(serv_addr));
   portno = atoi(argv[1]);
   serv_addr.sin_family = AF_INET;
   serv_addr.sin_addr.s_addr = INADDR_ANY;
   serv_addr.sin_port = htons(portno);
   if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) error("ERROR on binding");
   listen(sockfd,5);
   clilen = sizeof(cli_addr);
   while (1) {
      newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
      if (newsockfd < 0) error("ERROR on accept");
      pid = fork();
      if (pid < 0) error("ERROR on fork");
      if (pid == 0)  {
         
	 close(sockfd);
         dostuff(newsockfd);
	 exit(0);
      }
    
      else close(newsockfd);
    }

   return 0;
}
