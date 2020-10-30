#include "data.h"

u_int16_t size(data_t data) {

   u_int32_t i;
   u_int16_t filled;

   i = 0;
   filled = 0;

   while (i < SIZE) {
	   
      if ((*(data.database[i].id)).ID != NULL) filled++;
      i++;
   }

   return filled;
}

user_t init(ID_t id, bio_t bio, pub_t pub) {

   user_t new;
   u_int16_t i;

   new.id = malloc(sizeof(ID_t));
   new.bio = malloc(sizeof(bio_t));
   new.pub = malloc(sizeof(pub_t));
   
   for (i = 0; i < SABER_SEEDBYTES; i++) *((*(new.id)).ID + i) = *(id.ID + i);
   for (i = 0; i < BIOBYTES; i++) *((*(new.bio)).BIO + i) = *(bio.BIO + i);
   for (i = 0; i < SABER_PUBLICKEYBYTES; i++) *((*(new.pub)).PUB + i) = *(pub.PUB + i);
   
   return new;
}

u_int16_t hashIndex(ID_t id) {

   return ((size_t)id.ID) % SIZE;
}

bool exists(data_t data, ID_t id) {
   
   bool found;
   u_int32_t i;
   u_int16_t j;
   u_int16_t numEq;

   found = false;
   i = hashIndex(id);
   
   while (!found && i < SIZE) {

      numEq = 0;
      for (j = 0; j < SABER_SEEDBYTES; j++) {

         if (*((*(data.database[i].id)).ID + j) == *(id.ID + j)) numEq++;
      }
      
      if (numEq == SABER_SEEDBYTES) found = true;
      i++;
   }

   return found;
}

u_int16_t find(data_t data, ID_t id) {
   
   u_int16_t i;
   u_int16_t numEq; 
   u_int16_t j;
      
   i = hashIndex(id);
	
   while((*(data.database[i].id)).ID != NULL) {

      numEq = 0;
      for (j = 0; j < SABER_SEEDBYTES; j++) {
     
         if (*((*(data.database[i].id)).ID + j) == *(id.ID + j)) numEq++;
      }
   
      if (numEq == SABER_SEEDBYTES) return i;
      i++;
   }       
}

bool validate(data_t data, ID_t id, bio_t bio) {

   u_int16_t i;
   u_int16_t numEq;
   u_int16_t j;

   i = find(data, id);
   numEq = 0;
   
   for (j = 0; j < BIOBYTES; j++) {

      if (*((*(data.database[i].bio)).BIO + j) == *(bio.BIO + j)) numEq++;
   }

   if (numEq == BIOBYTES) return true;
   return false;
}

pub_t getPublicKey(data_t data, ID_t id) {

   u_int16_t i;

   i = find(data, id);
   return *(data.database[i].pub);
}

void insert(data_t data, ID_t id, bio_t bio, pub_t pub) {

   u_int16_t i;

   i = hashIndex(id);
   while ((*(data.database[i].id)).ID != NULL) i++;

   data.database[i] = init(id, bio, pub);
}

void empty(data_t data, ID_t id, bio_t bio) {

   u_int16_t i;
   
   if (validate(data, id, bio)) {

      i = find(data, id);
      free(data.database[i].id);
      free(data.database[i].bio);
      free(data.database[i].pub);
      data.database[i].id = NULL;
      data.database[i].bio = NULL;
      data.database[i].pub = NULL;
   }
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

   data_t data;
   ID_t id;
   bio_t bio;
   pub_t pub;
   u_int32_t i;
   
   int sockfd, newsockfd, portno, clilen, pid;
   struct sockaddr_in serv_addr, cli_addr;

   for (i = 0; i < SIZE; i++) {
      
      data.database[i].id = NULL;
      data.database[i].bio = NULL;
      data.database[i].pub = NULL;
   }

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

