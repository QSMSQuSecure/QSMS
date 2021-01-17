#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h>
#include <openssl/evp.h>

#include "../crypto/saber/Reference_Implementation_KEM/api.h"
#include "../crypto/saber/Reference_Implementation_KEM/rng.c"
#include "../crypto/saber/Reference_Implementation_KEM/pack_unpack.c"
#include "../crypto/saber/Reference_Implementation_KEM/poly.c"
#include "../crypto/saber/Reference_Implementation_KEM/fips202.c"
#include "../crypto/saber/Reference_Implementation_KEM/verify.c"
#include "../crypto/saber/Reference_Implementation_KEM/cbd.c"
#include "../crypto/saber/Reference_Implementation_KEM/SABER_indcpa.c"
#include "../crypto/saber/Reference_Implementation_KEM/kem.c"

#define PORT	8080 

int main() { 

    int sockfd; 
    unsigned char *rec;
    struct sockaddr_in servaddr, cliaddr;

    int iv_block;
    int ct_block;
    int full_block;
    int input_block;
    int shift;
    
    unsigned char *entropy;
    unsigned char *personal;
    unsigned char *spk;
    unsigned char *sk;
    unsigned char *ct;
    unsigned char *ss1;
    unsigned char *cpk;
    unsigned char *ss2;
    unsigned char *rand1;
    unsigned char *rand2;

    unsigned char *iv;
    unsigned char *tag;
    unsigned char *dt;
    unsigned char *final;
    EVP_CIPHER_CTX *ctx;

    int i;
    int j;
    int n;
    int len;

    rec = calloc(CRYPTO_PUBLICKEYBYTES + 1, 1);
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
    
    iv_block = 12;
    ct_block = 16;
    full_block = 32;
    input_block = 48;
    shift = 60;
    
    entropy = calloc(input_block, 1);
    personal = calloc(input_block, 1);
    cpk = calloc(CRYPTO_PUBLICKEYBYTES, 1);
    ct = calloc(CRYPTO_CIPHERTEXTBYTES, 1);
    ss1 = calloc(CRYPTO_BYTES, 1);
    spk = calloc(CRYPTO_PUBLICKEYBYTES, 1);
    sk = calloc(CRYPTO_SECRETKEYBYTES, 1);
    ss2 = calloc(CRYPTO_BYTES, 1);
    rand1 = calloc(full_block, 1);
    rand2 = calloc(full_block, 1);
    
    iv = calloc(iv_block, 1);
    tag = calloc(ct_block, 1);
    dt = calloc(ct_block, 1);
    final = calloc(full_block, 1);
    ctx = EVP_CIPHER_CTX_new();

    for (i = 0; i < input_block; i++) {

        entropy[i] = 0xff;
	personal[i] = 0xaa;
    }

    randombytes_init(entropy, personal, 1);
    crypto_kem_keypair(spk, sk);

    len = sizeof(cliaddr); //len is value/result 
    n = recvfrom(sockfd, (unsigned char *)rec, CRYPTO_CIPHERTEXTBYTES, MSG_WAITALL, ( struct sockaddr *) &cliaddr, &len); 
    rec[n] = '\0';

    memcpy(ct, rec, CRYPTO_CIPHERTEXTBYTES);
    crypto_kem_dec(ss1, ct, sk);
    
    for (i = 0; i < (CRYPTO_PUBLICKEYBYTES / ct_block) + !(!(CRYPTO_PUBLICKEYBYTES << shift)); i++) {

	n = recvfrom(sockfd, (unsigned char *)rec, full_block, MSG_WAITALL, (struct sockaddr *) &cliaddr, &len);
        rec[n] = '\0';

	for (j = 0; j < ct_block; j++) tag[j] = rec[ct_block + j];

        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, ss1, iv);
        EVP_DecryptUpdate(ctx, dt, &len, rec, ct_block);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, sizeof(tag), (void*)tag);
        n = EVP_DecryptFinal_ex(ctx, dt, &len);
        assert(n == 1);

        for (j = 0; j < ct_block; j++) cpk[(i * ct_block) + j] = dt[j];
    }
    
    crypto_kem_enc(ct, ss2, cpk);

    sendto(sockfd, (const unsigned char *)ct, CRYPTO_CIPHERTEXTBYTES, MSG_CONFIRM, (const struct sockaddr *) &cliaddr, sizeof(servaddr));

    for (i = 0; i < full_block / ct_block; i++) {

	n = recvfrom(sockfd, (unsigned char *)rec, full_block, MSG_WAITALL, (struct sockaddr *) &cliaddr, &len);
        rec[n] = '\0';

	for (j = 0; j < ct_block; j++) tag[j] = rec[ct_block + j];

        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, ss1, iv);
        EVP_DecryptUpdate(ctx, dt, &len, rec, ct_block);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, ct_block, (void*)tag);
        n = EVP_DecryptFinal_ex(ctx, dt, &len);
        assert(n == 1);

        for (j = 0; j < ct_block; j++) rand1[(i * ct_block) + j] = dt[j];
    }

    for (i = 0; i < full_block /ct_block; i++) {

        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, ss2, iv);
	EVP_EncryptUpdate(ctx, dt, &len, rand1 + (i * ct_block), ct_block);
	EVP_EncryptFinal_ex(ctx, dt, &len);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, ct_block, (void*)tag);

	for (j = 0; j < ct_block; j++) {
	    final[j] = dt[j];
	    final[ct_block + j] = tag[j];
	}
	sendto(sockfd, (const unsigned char *)final, full_block, MSG_CONFIRM, (const struct sockaddr *) &cliaddr, sizeof(servaddr));
    }

    randombytes(rand1, 32);
    for (i = 0; i < full_block /ct_block; i++) {

        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, ss1, iv);
	EVP_EncryptUpdate(ctx, dt, &len, rand1 + (i * ct_block), ct_block);
	EVP_EncryptFinal_ex(ctx, dt, &len);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, ct_block, (void*)tag);

	for (j = 0; j < ct_block; j++) {
	    final[j] = dt[j];
	    final[ct_block + j] = tag[j];
	}
	sendto(sockfd, (const unsigned char *)final, full_block, MSG_CONFIRM, (const struct sockaddr *) &cliaddr, sizeof(servaddr));
    }

    for (i = 0; i < full_block / ct_block; i++) {

	n = recvfrom(sockfd, (unsigned char *)rec, full_block, MSG_WAITALL, (struct sockaddr *) &cliaddr, &len);
        rec[n] = '\0';

	for (j = 0; j < ct_block; j++) tag[j] = rec[ct_block + j];

        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, ss2, iv);
        EVP_DecryptUpdate(ctx, dt, &len, rec, ct_block);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, ct_block, (void*)tag);
        n = EVP_DecryptFinal_ex(ctx, dt, &len);
        assert(n == 1);

        for (j = 0; j < ct_block; j++) rand2[(i * ct_block) + j] = dt[j];
    }

    for (i = 0; i < full_block; i++) assert(rand1[i] == rand2[i]);

    close(sockfd);
    return 0;
}
