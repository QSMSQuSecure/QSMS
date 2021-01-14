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
#include <stdio.h>
#include <openssl/evp.h>

#define PORT    8080 
#define MAXLINE CRYPTO_PUBLICKEYBYTES

int main() { 
    int sockfd;
    unsigned char *buffer;
    unsigned char *pk;
    unsigned char *sk;
    unsigned char *ct;
    unsigned char *ss;
    unsigned char *pt;
    unsigned char *iv;
    unsigned char *tag;
    unsigned char *ctext;
    EVP_CIPHER_CTX *ctx;
    struct sockaddr_in servaddr;
    int i;
    int n;
    int len;
    int ct_len;

    buffer = calloc(MAXLINE, 1);
    pk = calloc(CRYPTO_PUBLICKEYBYTES, 1);
    sk = calloc(CRYPTO_SECRETKEYBYTES, 1);
    ct = calloc(CRYPTO_CIPHERTEXTBYTES, 1);
    ss = calloc(CRYPTO_BYTES, 1);
    pt = (unsigned char *) "Hello Salesforce!";
    iv = calloc(12, 1);
    tag = calloc(16, 1);
    ctext = calloc(16, 1);
    ctx = EVP_CIPHER_CTX_new();

    crypto_kem_keypair(pk, sk);

    printf("Public Key: ");
    for (i = 0; i < CRYPTO_PUBLICKEYBYTES; i++) printf("%02x", pk[i]);
    printf("\n\n");

    // Creating socket file descriptor
    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        perror("socket creation failed");
	exit(EXIT_FAILURE);
    }
    memset(&servaddr, 0, sizeof(servaddr));
    // Filling server information
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(PORT);
    servaddr.sin_addr.s_addr = inet_addr("172.29.105.100");

    sendto(sockfd, (const unsigned char *)pk, MAXLINE, MSG_CONFIRM, (const struct sockaddr *) &servaddr, sizeof(servaddr));

    n = recvfrom(sockfd, (unsigned char *)buffer, CRYPTO_CIPHERTEXTBYTES, MSG_WAITALL, (struct sockaddr *) &servaddr, &len);
    buffer[n] = '\0';
    printf("Ciphertext: ");
    for (i = 0; i < CRYPTO_CIPHERTEXTBYTES; i++) {
	printf("%02x", buffer[i]);
    }
    printf("\n\n");
    memcpy(ct, buffer, CRYPTO_CIPHERTEXTBYTES);
    crypto_kem_dec(ss, ct, sk);
    printf("Shared Secret: ");
    for (i = 0; i < CRYPTO_BYTES; i++) {
	printf("%02x", ss[i]);
    }
    printf("\n\n");

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, ss, iv);
    EVP_EncryptUpdate(ctx, ctext, &len, pt, sizeof(pt));
    EVP_EncryptFinal_ex(ctx, ctext, &len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, sizeof(tag), (void*) tag);

    sendto(sockfd, (const unsigned char *)ctext, 8, MSG_CONFIRM, (const struct sockaddr *) &servaddr, sizeof(servaddr));

    printf("Sent: %s\n", pt);
    printf("Tag: ");
    for (i = 0; i < sizeof(tag); i++) printf("%02x", tag[i]);
    printf("\n");

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, ss, iv);
    EVP_EncryptUpdate(ctx, ctext, &len, pt + 8, 8);
    EVP_EncryptFinal_ex(ctx, ctext, &len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, sizeof(tag), (void*) tag);

    sendto(sockfd, (const unsigned char *)ctext, 8, MSG_CONFIRM, (const struct sockaddr *) &servaddr, sizeof(servaddr));

    printf("Tag: ");
    for (i = 0; i < sizeof(tag); i++) printf("%02x", tag[i]);
    printf("\n");
    
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, ss, iv);
    EVP_EncryptUpdate(ctx, ctext, &len, pt + 16, 8);
    EVP_EncryptFinal_ex(ctx, ctext, &len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, sizeof(tag), (void*) tag);

    sendto(sockfd, (const unsigned char *)ctext, 8, MSG_CONFIRM, (const struct sockaddr *) &servaddr, sizeof(servaddr));

    printf("Tag: ");
    for (i = 0; i < sizeof(tag); i++) printf("%02x", tag[i]);
    printf("\n");
    
    close(sockfd);
    return 0;
}
