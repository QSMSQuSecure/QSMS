#include "../crypto/saber/Reference_Implementation_KEM/api.h"
#include "../crypto/saber/Reference_Implementation_KEM/rng.c"
#include "../crypto/saber/Reference_Implementation_KEM/pack_unpack.c"
#include "../crypto/saber/Reference_Implementation_KEM/poly.c"
#include "../crypto/saber/Reference_Implementation_KEM/fips202.c"
#include "../crypto/saber/Reference_Implementation_KEM/verify.c"
#include "../crypto/saber/Reference_Implementation_KEM/cbd.c"
#include "../crypto/saber/Reference_Implementation_KEM/SABER_indcpa.c"
#include "../crypto/saber/Reference_Implementation_KEM/kem.c"

// Server side implementation of UDP client-server model 
#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h> 

#define PORT	8080 
#define MAXLINE CRYPTO_PUBLICKEYBYTES + 1

// Driver code 
int main() { 
    int sockfd; 
    unsigned char *buffer;
    struct sockaddr_in servaddr, cliaddr;
    unsigned char *pk;
    unsigned char *ct;
    unsigned char *ss;
    int i;

    buffer = calloc(MAXLINE, 1);
    pk = calloc(CRYPTO_PUBLICKEYBYTES, 1);
    ct = calloc(CRYPTO_CIPHERTEXTBYTES, 1);
    ss = calloc(CRYPTO_BYTES, 1);

    // Creating socket file descriptor
    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        perror("socket creation failed");
	exit(EXIT_FAILURE); 
    } 
    memset(&servaddr, 0, sizeof(servaddr));
    memset(&cliaddr, 0, sizeof(cliaddr)); 
    // Filling server information 
    servaddr.sin_family = AF_INET; // IPv4 
    servaddr.sin_addr.s_addr = INADDR_ANY; 
    servaddr.sin_port = htons(PORT); 
    // Bind the socket with the server address 
    if (bind(sockfd, (const struct sockaddr *) &servaddr, sizeof(servaddr)) < 0) { 
        perror("bind failed"); 
        exit(EXIT_FAILURE); 
    } 
    int len, n;
    len = sizeof(cliaddr); //len is value/result 
    n = recvfrom(sockfd, buffer, MAXLINE, MSG_WAITALL, ( struct sockaddr *) &cliaddr, &len); 
    buffer[n] = '\0';

    printf("Public Key: ");
    for (i = 0; i < CRYPTO_PUBLICKEYBYTES; i++) {
	printf("%02x", buffer[i]);
    }
    printf("\n");

    memcpy(pk, buffer, CRYPTO_PUBLICKEYBYTES);
    crypto_kem_enc(ct, ss, pk);
    
    printf("Ciphertext: ");
    for (i = 0; i < CRYPTO_CIPHERTEXTBYTES; i++) printf("%02x", ct[i]);
    printf("\n");

    printf("Shared Secret: ");
    for (i = 0; i < CRYPTO_BYTES; i++) printf("%02x", ss[i]);
    printf("\n");

    sendto(sockfd, (const unsigned char *)ct, CRYPTO_CIPHERTEXTBYTES, MSG_CONFIRM, (const struct sockaddr *) &cliaddr, len);

    return 0;
}
