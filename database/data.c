#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "../PQC_IBE/Reference_Implementation_KEM/SABER_params.h"

#define SIZE 200000
#define BIOBYTES 128



typedef struct DataItem {
   u_int8_t ID[SABER_SEEDBYTES];
   u_int8_t bio[BIOBYTES];
   u_int8_t pub[SABER_PUBLICKEYBYTES];
} dataItem;

dataItem *newItem(u_int8_t ID[SABER_SEEDBYTES], u_int8_t bio[BIOBYTES], u_int8_t pub[SABER_PUBLICKEYBYTES]) {
   dataItem *new;
   int i;

   new = (dataItem*) malloc(sizeof(dataItem));
   for (i = 0; i < SABER_SEEDBYTES; i++) new->ID[i] = ID[i];
   for (i = 0; i < BIOBYTES; i++) new->bio[i] = bio[i];
   for (i = 0; i < SABER_PUBLICKEYBYTES; i++) new->pub[i] = pub[i];
   return new;
}

int hashCode(u_int8_t ID[SABER_SEEDBYTES]) {
   return ((size_t)ID) % SIZE;
}

dataItem *search(dataItem *database[SIZE], u_int8_t ID[SABER_SEEDBYTES], u_int8_t bio[BIOBYTES]) {
   
   int i;
   int numEq;
	
   //get the hash 
   int hashIndex;
   hashIndex = hashCode(ID);
	
   //move in array until an empty 
   while(database[hashIndex] != NULL) {

      numEq = 0;
      if (database[hashIndex]->ID != NULL) {
         for (i = 0; i < SABER_SEEDBYTES; i++) {
            if (database[hashIndex]->ID[i] == ID[i]) numEq++;
         }
	 for (i = 0; i < BIOBYTES; i++) {
	    if (database[hashIndex]->bio[i] == bio[i]) numEq++;
	 }
      }
      if (numEq == SABER_SEEDBYTES + BIOBYTES) return database[hashIndex];
      
			
      //go to next cell
      ++hashIndex;
		
      //wrap around the table
      hashIndex %= SIZE;
   }
	
   return NULL;        
}

void insert(dataItem *database[SIZE], u_int8_t ID[SABER_SEEDBYTES], u_int8_t bio[BIOBYTES], u_int8_t pub[SABER_PUBLICKEYBYTES]) {

   int i;
   int hashIndex;
   dataItem *item;

   item = newItem(ID, bio, pub);

   //get the hash 
   hashIndex = hashCode(ID);

   //move in array until an empty cell
   while(database[hashIndex] != NULL) {
      //go to next cell
      hashIndex++;
		
      //wrap around the table
      hashIndex %= SIZE;
   }

   database[hashIndex] = item;
   return;
}

void delete(dataItem *database[SIZE], u_int8_t ID[SABER_SEEDBYTES], u_int8_t bio[BIOBYTES]) {

   int hashIndex;
   int numEq;
   int i;

   //get the hash 
   hashIndex = hashCode(ID);

   //move in array until an empty
   while(database[hashIndex] != NULL) {

      numEq = 0;
      if (database[hashIndex]->ID != NULL) {
         for (i = 0; i < SABER_SEEDBYTES; i++) {
            if (database[hashIndex]->ID[i] == ID[i]) numEq++;
         }
	 for (i = 0; i < BIOBYTES; i++) {
            if (database[hashIndex]->bio[i] == bio[i]) numEq++;
	 }
      }
      if (numEq == SABER_SEEDBYTES + BIOBYTES) {
         free((void*)(database[hashIndex]));
	 database[hashIndex] = NULL;
      }
      //go to next cell
      ++hashIndex;
		
      //wrap around the table
      hashIndex %= SIZE;
   }

   return;
}

void error(char *msg) {
   perror(msg);
   exit(1);
}

void dostuff (int sock)
{
   int n;
   char buffer[256];
      
   bzero(buffer,256);
   n = read(sock,buffer,255);
   if (n < 0) error("ERROR reading from socket");
   printf("Here is the message: %s\n",buffer);
   n = write(sock,"I got your message",18);
   if (n < 0) error("ERROR writing to socket");
}

int main(int argc, char *argv[]) {

   dataItem *database[SIZE];
   u_int8_t ID[SABER_SEEDBYTES];
   u_int8_t bio[BIOBYTES];
   u_int8_t pub[SABER_PUBLICKEYBYTES];
   int i;
   int sockfd, newsockfd, portno, clilen, pid;
   struct sockaddr_in serv_addr, cli_addr;

   for (i = 0; i < SIZE; i++) database[i] = NULL;

   if (argc < 2) {
       fprintf(stderr,"ERROR, no port provided\n");
       exit(1);
   }
   sockfd = socket(AF_INET, SOCK_STREAM, 0);
   if (sockfd < 0) 
      error("ERROR opening socket");
   bzero((char *) &serv_addr, sizeof(serv_addr));
   portno = atoi(argv[1]);
   serv_addr.sin_family = AF_INET;
   serv_addr.sin_addr.s_addr = INADDR_ANY;
   serv_addr.sin_port = htons(portno);
   if (bind(sockfd, (struct sockaddr *) &serv_addr,
            sizeof(serv_addr)) < 0) 
            error("ERROR on binding");
   listen(sockfd,5);
   clilen = sizeof(cli_addr);
   while (1) {
       newsockfd = accept(sockfd, 
             (struct sockaddr *) &cli_addr, &clilen);
       if (newsockfd < 0) 
           error("ERROR on accept");
       pid = fork();
       if (pid < 0)
           error("ERROR on fork");
       if (pid == 0)  {
           close(sockfd);
           dostuff(newsockfd);
           exit(0);
       }
       else close(newsockfd);
   }
   
   return 0;
}

