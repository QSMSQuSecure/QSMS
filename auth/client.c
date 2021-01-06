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
/*
 *  * Copyright 2012-2016 The OpenSSL Project Authors. All Rights Reserved.
 *   *
 *    * Licensed under the Apache License 2.0 (the "License").  You may not use
 *     * this file except in compliance with the License.  You can obtain a copy
 *      * in the file LICENSE in the source distribution or at
 *       * https://www.openssl.org/source/license.html
 *        */

/*
 *  * Simple AES GCM test program, uses the same NIST data used for the FIPS
 *   * self test but uses the application level EVP APIs.
 *    */
#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

/* AES-GCM test data from NIST public test vectors */

static const unsigned char gcm_iv[] = {
	    0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84
};

static const unsigned char gcm_pt[] = {
	    0xf5, 0x6e, 0x87, 0x05, 0x5b, 0xc3, 0x2d, 0x0e, 0xeb, 0x31, 0xb2, 0xea,
	        0xcc, 0x2b, 0xf2, 0xa5
};

static const unsigned char gcm_aad[] = {
	    0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34, 0xb4, 0x9b, 0xdb, 0x37, 0x0c, 0x43,
	        0x7f, 0xec, 0x78, 0xde
};

static const unsigned char gcm_ct[] = {
	    0xf7, 0x26, 0x44, 0x13, 0xa8, 0x4c, 0x0e, 0x7c, 0xd5, 0x36, 0x86, 0x7e,
	        0xb9, 0xf2, 0x17, 0x36
};

static const unsigned char gcm_tag[] = {
	    0x67, 0xba, 0x05, 0x10, 0x26, 0x2a, 0xe4, 0x87, 0xd7, 0x37, 0xee, 0x62,
	        0x98, 0xf7, 0x7e, 0x0c
};

void aes_gcm_encrypt(const unsigned char *ss)
{
    EVP_CIPHER_CTX *ctx;
    int outlen, tmplen;
    unsigned char outbuf[1024];
    printf("AES GCM Encrypt:\n");
    printf("Plaintext:\n");
    BIO_dump_fp(stdout, gcm_pt, sizeof(gcm_pt));
    ctx = EVP_CIPHER_CTX_new();
    /* Set cipher type and mode */
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    /* Set IV length if default 96 bits is not appropriate */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(gcm_iv), NULL);
    /* Initialise key and IV */
    EVP_EncryptInit_ex(ctx, NULL, NULL, ss, gcm_iv);
    /* Zero or more calls to specify any AAD */
    EVP_EncryptUpdate(ctx, NULL, &outlen, gcm_aad, sizeof(gcm_aad));
    /* Encrypt plaintext */
    EVP_EncryptUpdate(ctx, outbuf, &outlen, gcm_pt, sizeof(gcm_pt));
    /* Output encrypted block */
    printf("Ciphertext:\n");
    BIO_dump_fp(stdout, outbuf, outlen);
    /* Finalise: note get no output for GCM */
    EVP_EncryptFinal_ex(ctx, outbuf, &outlen);
    /* Get tag */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, outbuf);
    /* Output tag */
    printf("Tag:\n");
    BIO_dump_fp(stdout, outbuf, 16);
    EVP_CIPHER_CTX_free(ctx);
}

// Driver code 
int main() { 
    int sockfd;
    unsigned char *buffer;
    unsigned char *pk;
    unsigned char *sk;
    unsigned char *ct;
    unsigned char *ss;
    struct sockaddr_in servaddr;
    int i;

    buffer = calloc(MAXLINE, 1);
    pk = calloc(CRYPTO_PUBLICKEYBYTES, 1);
    sk = calloc(CRYPTO_SECRETKEYBYTES, 1);
    ct = calloc(CRYPTO_CIPHERTEXTBYTES, 1);
    ss = calloc(CRYPTO_BYTES, 1);

    crypto_kem_keypair(pk, sk);

    printf("Public Key: ");
    for (i = 0; i < CRYPTO_PUBLICKEYBYTES; i++) printf("%02x", pk[i]);
    printf("\n");

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

    int n, len;
    sendto(sockfd, (const unsigned char *)pk, MAXLINE, MSG_CONFIRM, (const struct sockaddr *) &servaddr, sizeof(servaddr));

    n = recvfrom(sockfd, (unsigned char *)buffer, CRYPTO_CIPHERTEXTBYTES, MSG_WAITALL, (struct sockaddr *) &servaddr, &len);
    buffer[n] = '\0';
    printf("Ciphertext: ");
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

    aes_gcm_encrypt(ss);

    close(sockfd);
    return 0;
}
