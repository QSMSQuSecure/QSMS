// Client side implementation of UDP client-server model 
#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h> 

#include "../crypto/saber/Reference_Implementation_KEM/api.h"
#include "../crypto/saber/Reference_Implementation_KEM/rng.c"
#include "../crypto/saber/Reference_Implementation_KEM/pack_unpack.c"
#include "../crypto/saber/Reference_Implementation_KEM/poly.c"
#include "../crypto/saber/Reference_Implementation_KEM/fips202.c"
#include "../crypto/saber/Reference_Implementation_KEM/verify.c"
#include "../crypto/saber/Reference_Implementation_KEM/cbd.c"
#include "../crypto/saber/Reference_Implementation_KEM/SABER_indcpa.c"
#include "../crypto/saber/Reference_Implementation_KEM/kem.c"

#define PORT    8080 
#define MAXLINE CRYPTO_PUBLICKEYBYTES + 1

// Driver code 
int main() { 
    int sockfd;
    char buffer[MAXLINE];
    unsigned char *pk;
    unsigned char *sk;
    unsigned char *ct;
    unsigned char *ss;
    struct sockaddr_in servaddr;
    int i;

    pk = calloc(CRYPTO_PUBLICKEYBYTES, 1);
    sk = calloc(CRYPTO_SECRETKEYBYTES, 1);
    ct = calloc(CRYPTO_CIPHERTEXTBYTES, 1);
    ss = calloc(CRYPTO_BYTES, 1);

    crypto_kem_keypair(pk, sk);

    // Creating socket file descriptor
    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        perror("socket creation failed");
	exit(EXIT_FAILURE);
    }
    memset(&servaddr, 0, sizeof(servaddr));
    // Filling server information
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(PORT);
    servaddr.sin_addr.s_addr = inet_addr("172.29.96.212");
    int n, len;
    sendto(sockfd, (const char *)pk, MAXLINE, MSG_CONFIRM, (const struct sockaddr *) &servaddr, sizeof(servaddr));
    printf("Public Key sent.\n");
    n = recvfrom(sockfd, (char *)buffer, MAXLINE, MSG_WAITALL, (struct sockaddr *) &servaddr, &len);
    buffer[n] = '\0';
    printf("Server: ");
    for (i = 0; i < CRYPTO_CIPHERTEXTBYTES; i++) {
	printf("%02x", buffer[i]);
    }
    printf("\n");
    memcpy(ct, buffer, CRYPTO_CIPHERTEXTBYTES);
    crypto_kem_dec(ss, ct, sk);
    printf("Shared Secret: ");
    for (i = 0; i < CRYPTO_BYTES; i++) {
	printf("%02x", ss[i]);
    }
    printf("\n");
    close(sockfd);
    return 0;
}
