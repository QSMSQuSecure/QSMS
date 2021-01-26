/* 
 * Chris Cap
 * Copyright 2021 by QuSecure, Inc.
 */

// Load standard libraries
#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h>
#include <openssl/evp.h>
#include <assert.h>

// Load Key Encapsulation Mechanism files
#include "../crypto/kyber/Optimized_Implementation/crypto_kem/kyber512/api.h"
#include "../crypto/kyber/Optimized_Implementation/crypto_kem/kyber512/cbd.c"
#include "../crypto/kyber/Optimized_Implementation/crypto_kem/kyber512/fips202.c"
#include "../crypto/kyber/Optimized_Implementation/crypto_kem/kyber512/indcpa.c"
#include "../crypto/kyber/Optimized_Implementation/crypto_kem/kyber512/kem.c"
#include "../crypto/kyber/Optimized_Implementation/crypto_kem/kyber512/ntt.c"
#include "../crypto/kyber/Optimized_Implementation/crypto_kem/kyber512/poly.c"
#include "../crypto/kyber/Optimized_Implementation/crypto_kem/kyber512/polyvec.c"
#include "../crypto/kyber/Optimized_Implementation/crypto_kem/kyber512/reduce.c"
#include "../crypto/kyber/Optimized_Implementation/crypto_kem/kyber512/rng.c"
#include "../crypto/kyber/Optimized_Implementation/crypto_kem/kyber512/verify.c"
#include "../crypto/kyber/Optimized_Implementation/crypto_kem/kyber512/symmetric-shake.c"

#define PORT	8443 

int main() { 

    int sockfd; // Socket
    unsigned char *rec; // Buffer
    struct sockaddr_in servaddr, cliaddr; // Client and server addresses

    int iv_block; // Length of the AES initialization vector
    int ct_block; // Length of the AES ciphertext
    int full_block; // Combined length of ciphertext and authentication tag
    int input_block; // Length of inputs to randombytes_init()
    int shift; // Shift constant
    
    unsigned char *entropy; // Entropy input to randombytes_init()
    unsigned char *personal; // Personalization string input to randombytes_init()
    unsigned char *spk; // Server KEM public key
    unsigned char *sk; // KEM secret key
    unsigned char *ct; // KEM ciphertext
    unsigned char *ss1; // First shared secret
    unsigned char *cpk; // Client KEM public key
    unsigned char *ss2; // Second shared secret
    unsigned char *rand1; // Sent string of random bits
    unsigned char *rand2; // Received string of random bits

    unsigned char *iv1; // AES initialization vector
    unsigned char *iv2;
    unsigned char *tag; // AES authentication tag
    unsigned char *dt; // Decrypted/Encrypted text
    unsigned char *final; // Block containing AES ciphertext and authentication tag
    EVP_CIPHER_CTX *ctx; // AES ciphertext

    int i; // Loop counter
    int j; // Loop counter
    int n; // Used by AES and UDP
    int len; // Used by UDP

    // Initialize buffer for maximum input size with room for NULL terminator
    rec = calloc(CRYPTO_PUBLICKEYBYTES + 1, 1);

    // Creating socket file descriptor
    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        perror("socket creation failed");
	exit(EXIT_FAILURE); 
    }

    // Initialize client and server addresses
    memset(&servaddr, 0, sizeof(servaddr));
    memset(&cliaddr, 0, sizeof(cliaddr));

    // Fill in server information 
    servaddr.sin_family = AF_INET; // IPv4 
    servaddr.sin_addr.s_addr = INADDR_ANY; 
    servaddr.sin_port = htons(PORT); 
    
    // Bind the socket with the server address 
    if (bind(sockfd, (const struct sockaddr *) &servaddr, sizeof(servaddr)) < 0) { 
        perror("bind failed"); 
        exit(EXIT_FAILURE); 
    } 
    
    // Initialize constants
    iv_block = 12;
    ct_block = 16;
    full_block = 32;
    input_block = 48;
    shift = 60;
    
    // Initialize variables used by KEM
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
    
    // Initialize variables used by AES
    iv1 = calloc(iv_block, 1);
    iv2 = calloc(iv_block, 1);
    tag = calloc(ct_block, 1);
    dt = calloc(ct_block, 1);
    final = calloc(full_block, 1);
    ctx = EVP_CIPHER_CTX_new();

    // Set randombytes_init() inputs
    for (i = 0; i < input_block; i++) {

        entropy[i] = 0xff;
	personal[i] = 0xaa;
    }

    // Prepare the PRNG
    randombytes_init(entropy, personal, 1);

    // Generate KEM keypair
    crypto_kem_keypair(spk, sk);

    // Listen for KEM ciphertext
    len = sizeof(cliaddr);
    n = recvfrom(sockfd, (unsigned char *)rec, CRYPTO_CIPHERTEXTBYTES, MSG_WAITALL, ( struct sockaddr *) &cliaddr, &len); // Step 2
    rec[n] = '\0';

    // Copy buffer to ciphertext variable
    memcpy(ct, rec, CRYPTO_CIPHERTEXTBYTES);

    // Decapsulate the first shared secret
    crypto_kem_dec(ss1, ct, sk); // Step 3
    
    // Listen for the client's KEM public key
    for (i = 0; i < (CRYPTO_PUBLICKEYBYTES / ct_block) + !(!(CRYPTO_PUBLICKEYBYTES << shift)); i++) {

	n = recvfrom(sockfd, (unsigned char *)rec, full_block, MSG_WAITALL, (struct sockaddr *) &cliaddr, &len); // Step 5
        rec[n] = '\0';

        for (j = 0; j < ct_block; j++) tag[j] = rec[ct_block + j];

	// Step 6
	// Symmetrically decrypt the public key with the first shared secret
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, ss1, iv1);
        EVP_DecryptUpdate(ctx, dt, &len, rec, ct_block);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, ct_block, (void*)tag);
        n = EVP_DecryptFinal_ex(ctx, dt, &len);
        assert(n == 1); // Authenticate the ciphertext

        iv1[iv_block - 1] += (unsigned char) 0x01;

        for (j = 0; j < ct_block; j++) cpk[(i * ct_block) + j] = dt[j]; // Store the client's KEM public key
    }
    
    // Encapsulate the second shared secret
    crypto_kem_enc(ct, ss2, cpk); // Step 7

    // Send ciphertext to client
    sendto(sockfd, (const unsigned char *)ct, CRYPTO_CIPHERTEXTBYTES, MSG_CONFIRM, (const struct sockaddr *) &cliaddr, sizeof(servaddr)); // Step 8

    // Listen for random bytes from client
    for (i = 0; i < full_block / ct_block; i++) {

	n = recvfrom(sockfd, (unsigned char *)rec, full_block, MSG_WAITALL, (struct sockaddr *) &cliaddr, &len); // Step 12
        rec[n] = '\0';

	for (j = 0; j < ct_block; j++) tag[j] = rec[ct_block + j]; // Set the authentication tag

	// Step 13
	// Symmetrically decrypt the random bytes with the first shared secret 
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, ss1, iv1);
        EVP_DecryptUpdate(ctx, dt, &len, rec, ct_block);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, ct_block, (void*)tag);
        n = EVP_DecryptFinal_ex(ctx, dt, &len);
        assert(n == 1); // Authenticate the ciphertext

        iv1[iv_block - 1] += (unsigned char) 0x01;

        for (j = 0; j < ct_block; j++) rand2[(i * ct_block) + j] = dt[j]; // Store the random bytes
    }

    // Send the random bytes to the client
    for (i = 0; i < full_block /ct_block; i++) {

	// Step 14
	// Symmetrically encrypt the random bytes with the second shared secret
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, ss2, iv2);
	EVP_EncryptUpdate(ctx, dt, &len, rand2 + (i * ct_block), ct_block);
	EVP_EncryptFinal_ex(ctx, dt, &len);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, ct_block, (void*)tag);

        iv2[iv_block - 1] += (unsigned char) 0x01;

	// Format the block
	for (j = 0; j < ct_block; j++) {
	    final[j] = dt[j];
	    final[ct_block + j] = tag[j];
	}

	sendto(sockfd, (const unsigned char *)final, full_block, MSG_CONFIRM, (const struct sockaddr *) &cliaddr, sizeof(servaddr)); // Step 15
    }

    // Random bytes used for authentication
    randombytes(rand1, 32); // Step 18

    // Send the randombytes to the client
    for (i = 0; i < full_block /ct_block; i++) {

	// Step 19
	// Symmetrically encrypt the random bytes with the first shared secret
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, ss1, iv1);
	EVP_EncryptUpdate(ctx, dt, &len, rand1 + (i * ct_block), ct_block);
	EVP_EncryptFinal_ex(ctx, dt, &len);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, ct_block, (void*)tag);

        iv1[iv_block - 1] += (unsigned char) 0x01;
	
	// Format the block
	for (j = 0; j < ct_block; j++) {
	    final[j] = dt[j];
	    final[ct_block + j] = tag[j];
	}

	sendto(sockfd, (const unsigned char *)final, full_block, MSG_CONFIRM, (const struct sockaddr *) &cliaddr, sizeof(servaddr)); // Step 20
    }

    // Listen for random bytes from the client
    for (i = 0; i < full_block / ct_block; i++) {

	n = recvfrom(sockfd, (unsigned char *)rec, full_block, MSG_WAITALL, (struct sockaddr *) &cliaddr, &len); // Step 23
        rec[n] = '\0';

	for (j = 0; j < ct_block; j++) tag[j] = rec[ct_block + j]; // Set the authentication tag

	// Step 24
	// Symmetrically decrypt the random bytes using the second shared secret
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, ss2, iv2);
        EVP_DecryptUpdate(ctx, dt, &len, rec, ct_block);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, ct_block, (void*)tag);
        n = EVP_DecryptFinal_ex(ctx, dt, &len);
        assert(n == 1); // Authenticate the ciphertext

        iv2[iv_block - 1] += (unsigned char) 0x01;
        
	for (j = 0; j < ct_block; j++) rand2[(i * ct_block) + j] = dt[j]; // Store the random bytes
    }

    // Compare the two strings of random bytes to ensure they match
    for (i = 0; i < full_block; i++) assert(rand1[i] == rand2[i]); // Step 25

    free(rec);
    free(entropy);
    free(personal);
    free(spk);
    free(sk);
    free(ct);
    free(ss1);
    free(cpk);
    free(ss2);
    free(rand1);
    free(rand2);

    free(iv1);
    free(iv2);
    free(tag);
    free(dt);
    free(final);
    EVP_CIPHER_CTX_free(ctx);

    // Close the socket
    close(sockfd);
    return 0;
}
