#include "database.h"
#include "../crypto/saber/Reference_Implementation_KEM/SABER_indcpa.c"
#include "../crypto/saber/Reference_Implementation_KEM/poly.c"
#include "../crypto/saber/Reference_Implementation_KEM/pack_unpack.c"
#include "../crypto/saber/Reference_Implementation_KEM/rng.c"
#include "../crypto/saber/Reference_Implementation_KEM/fips202.c"
#include "../crypto/saber/Reference_Implementation_KEM/cbd.c"

pub_t *readBuf(data_t *data, buffer_t *buf) {

   u_int16_t i;
   read_t *read;
   write_t *write;

   read = (read_t*) malloc(sizeof(read_t));
   write = (write_t*) malloc(sizeof(write_t));
   read->id = (ID_t*) malloc(sizeof(ID_t));
   write->id = (ID_t*) malloc(sizeof(ID_t));
   write->bio = (bio_t*) malloc(sizeof(bio_t));

   if (buf->input[0] == 0x00) {

      free(write->id);
      free(write->bio);
      free(write);

      for (i = 0; i < READSIZE; i++) read->id->ID[i] = buf->input[i + 1];
      return userReadPub(data, read);
   }

   else if (buf->input[0] == 0x01) {

      free(read->id);
      free(read);

      for (i = 0; i < READSIZE; i++) write->id->ID[i] = buf->input[i + 1];
      for (i = READSIZE; i < WRITESIZE; i++) write->bio->BIO[i - READSIZE] = buf->input[i + 1]; 
      return userWrite(data, write);
   }

   free(read->id);
   free(read);
   free(write->id);
   free(write->bio);
   free(write);

   return NULL;
}

pub_t *userReadPub(data_t *data, read_t *input) {

   if (!(exists(data, input))) {

      free(input->id);
      free(input);
      return NULL;
   }

   return getPublicKey(data, input);
}

pub_t *userWrite(data_t *data, write_t *input) {

   read_t *output;
   pub_t *pk;
   u_int8_t sk[SABER_INDCPA_SECRETKEYBYTES];
   u_int16_t i;

   pk = (pub_t*) malloc(sizeof(pub_t));

   output = (read_t*) malloc(sizeof(read_t));
   output->id = (ID_t*) malloc(sizeof(ID_t));

   for (i = 0; i < READSIZE; i++) output->id->ID[i] = input->id->ID[i];

   if (exists(data, output)) {

      free(output->id);
      free(output);
      free(input->id);
      free(input->bio);
      free(input);
      return NULL;
   }

   indcpa_kem_keypair(pk->PUB, sk);
   // Do something with sk

   insert(data, input, pk);

   free(input->id);
   free(input->bio);
   free(input);

   free(pk);

   return getPublicKey(data, output);
}

/*pub_t *userReadSec(data_t *data, write_t *input) {

   if (!(exists(data, input->id))) {

      free(input->id);
      free(input);
      free(write->id);
      free(write->bio);
      free(write);
      return NULL;
   }
   
   if (!(validate(data, input->id, input->bio))) {

      free(input->id);
      free(input);
      free(write->id);
      free(write->bio);
      free(write);
      return NULL;
   }

}*/
  
void error(char *msg) {
   
   perror(msg);
   exit(1);
}

void dostuff (data_t *data, int sock) {
   
   int n;
   buffer_t *buf;
   pub_t *key;
   u_int16_t i;

   buf = (buffer_t*) malloc(sizeof(buffer_t));
   bzero(buf->input, BUFFERSIZE);
   n = read(sock, buf->input, BUFFERSIZE - 1);
   for (i = 0; i < READSIZE; i++) buf->input[i] -= (u_int8_t)48;
   if (n < 0) error("ERROR reading from socket");
   key = readBuf(data, buf);
   for (i = 0; i < READSIZE; i++) printf("%u,", key->PUB[i]); printf("\n");
   free(buf);
   n = write(sock,"I got your message",18);
   if (n < 0) error("ERROR writing to socket");
}

int main(int argc, char *argv[]) {

   int sockfd, newsockfd, portno, clilen, pid;
   struct sockaddr_in serv_addr, cli_addr;

   data_t *data;
   data = init();

   if (argc < 2) {
      fprintf(stderr,"ERROR, no port provided\n");
      exit(1);
   }
   sockfd = socket(AF_INET, SOCK_STREAM, 0);
   if (sockfd < 0) error("ERROR opening socket");
   bzero((unsigned char *) &serv_addr, sizeof(serv_addr));
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
         dostuff(data, newsockfd);
	 exit(0);
      }
    
      else close(newsockfd);
    }

   freeData(data);
   return 0;
}
