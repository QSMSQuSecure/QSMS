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
	    0xfb, 0xd7, 0xb8, 0x0b, 0xd3, 0x1b, 0x6e, 0x88, 0x5f, 0x70, 0x91, 0xd6,
	        0x6c, 0x41, 0x0a, 0xd8
};

static const unsigned char gcm_tag[] = {
	    0x80, 0x0c, 0x71, 0x55, 0xca, 0xff, 0x5d, 0x62, 0xf1, 0x15, 0x51, 0x56,
	        0xd4, 0x4f, 0x17, 0x88
};

void aes_gcm_decrypt(const unsigned char *ss)
{
    EVP_CIPHER_CTX *ctx;
    int outlen, tmplen, rv;
    unsigned char outbuf[1024];
    printf("AES GCM Decrypt:\n");
    printf("Ciphertext:\n");
    BIO_dump_fp(stdout, gcm_ct, sizeof(gcm_ct));
    ctx = EVP_CIPHER_CTX_new();
    /* Select cipher */
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    /* Set IV length, omit for 96 bits */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(gcm_iv), NULL);
    /* Specify key and IV */
    EVP_DecryptInit_ex(ctx, NULL, NULL, ss, gcm_iv);
    /* Zero or more calls to specify any AAD */
    EVP_DecryptUpdate(ctx, NULL, &outlen, gcm_aad, sizeof(gcm_aad));
    /* Decrypt plaintext */
    EVP_DecryptUpdate(ctx, outbuf, &outlen, gcm_ct, sizeof(gcm_ct));
    /* Output decrypted block */
    printf("Plaintext:\n");
    BIO_dump_fp(stdout, outbuf, outlen);
    /* Set expected tag value. */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, sizeof(gcm_tag), (void *)gcm_tag);
    /* Finalise: note get no output for GCM */
    rv = EVP_DecryptFinal_ex(ctx, outbuf, &outlen);
    printf("Tag Verify %s\n", rv > 0 ? "Successful!" : "Failed!");
    EVP_CIPHER_CTX_free(ctx);
}

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

    aes_gcm_decrypt(ss);

    return 0;
}
