/*
 * Chris Cap
 * Copyright 2021 by QuSecure, Inc.
 */

// Load standard libraries
#include <time.h>
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

#define PORT    8443 

int main() { 
    
    int sockfd;  // Socket
    unsigned char *rec; // Buffer
    struct sockaddr_in servaddr; // Server address
    
    int iv_block; // Length of the AES initialization vector
    int ct_block; // Length of the AES ciphertext
    int full_block; // Combined length of ciphertext and authentication tag
    int input_block; // Length of inputs to randombytes_init()
    int shift; // Shift constant
    
    unsigned char *entropy; // Entropy input to randombytes_init()
    unsigned char *personal; // Personalization string input to randombytes_init()
    unsigned char *spk; // Server KEM public key
    unsigned char *ct; // KEM ciphertext
    unsigned char *ss1; // First shared secret
    unsigned char *cpk; // Client KEM public key
    unsigned char *sk; // KEM secret key
    unsigned char *ss2; // Second shared secret
    unsigned char *rand1; // Sent string of random bits
    unsigned char *rand2; // Received string of random bits

    unsigned char *iv; // AES initialization vector
    unsigned char *tag; // AES authentication tag
    unsigned char *et; // Encrypted/Decrypted text
    unsigned char *final; // Block containing AES ciphertext and authentication tag
    EVP_CIPHER_CTX *ctx; // AES ciphertext
        
    FILE *in; // Server KEM public key storage
    
    int i; // Loop counter
    int j; // Loop counter
    int n; // Used by AES and UDP
    int len; // Used by UDP

    clock_t start;
    clock_t end;

    start = clock();

    // Initialize buffer for maximum input size with room for NULL terminator
    rec = calloc(CRYPTO_PUBLICKEYBYTES + 1, 1);

    // Creating socket file descriptor
    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        perror("socket creation failed");
	exit(EXIT_FAILURE);
    }

    // Initialize server address
    memset(&servaddr, 0, sizeof(servaddr));

    // Fill in server information
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(PORT);
    servaddr.sin_addr.s_addr = inet_addr("172.28.221.223"); // Change to match server
    
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
    sk = calloc(CRYPTO_SECRETKEYBYTES, 1);
    ct = calloc(CRYPTO_CIPHERTEXTBYTES, 1);
    ss1 = calloc(CRYPTO_BYTES, 1);
    spk = calloc(CRYPTO_PUBLICKEYBYTES, 1);
    ss2 = calloc(CRYPTO_BYTES, 1);
    rand1 = calloc(full_block, 1);
    rand2 = calloc(full_block, 1);
    
    // Initialize variables used by AES
    iv = calloc(iv_block, 1);
    tag = calloc(ct_block, 1);
    et = calloc(ct_block, 1);
    final = calloc(full_block, 1);
    ctx = EVP_CIPHER_CTX_new();

    // Read server public key from file
    in = fopen("server.key", "r");
    fread(spk, 1, CRYPTO_PUBLICKEYBYTES, in);
    fclose(in);

    // Prepare the PRNG
    randombytes_init(entropy, personal, 1);

    // Generate KEM keypair
    crypto_kem_keypair(cpk, sk);

    // Encapsulate the first shared secret
    crypto_kem_enc(ct, ss1, spk); // Step 1

    // Send the ciphertext to the server
    sendto(sockfd, (const unsigned char *)ct, CRYPTO_CIPHERTEXTBYTES, MSG_CONFIRM, (const struct sockaddr *) &servaddr, sizeof(servaddr)); // Step 2

    // Send KEM public key to server
    for (i = 0; i < (CRYPTO_PUBLICKEYBYTES / ct_block) + !(!(CRYPTO_PUBLICKEYBYTES << shift)); i++) {

	// Step 4
	// Symmetrically encrypt the public key with the first shared secret
	EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, ss1, iv);
        EVP_EncryptUpdate(ctx, et, &len, cpk + (i * ct_block), ct_block);
        EVP_EncryptFinal_ex(ctx, et, &len);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, ct_block, (void*)tag);

	// Format the block
        for (j = 0; j < ct_block; j++) {
	    final[j] = et[j];
	    final[ct_block + j] = tag[j];
	}

        sendto(sockfd, (const unsigned char *)final, full_block, MSG_CONFIRM, (const struct sockaddr *) &servaddr, sizeof(servaddr)); // Step 5
    }

    // Listen for ciphertext from the server
    n = recvfrom(sockfd, (unsigned char *)rec, CRYPTO_CIPHERTEXTBYTES, MSG_WAITALL, (struct sockaddr *) &servaddr, &len); // Step 8
    rec[n] = '\0';

    // Copy the buffer to the ciphertext variable
    memcpy(ct, rec, CRYPTO_CIPHERTEXTBYTES);

    // Decapsulate the second shared secret
    crypto_kem_dec(ss2, ct, sk); // Step 9
    
    // Random bytes used for authentication
    randombytes(rand1, 32); // Step 10

    // Send the random bytes to the server
    for (i = 0; i < full_block / ct_block; i++) {

	// Step 11
	// Symmetrically encrypt the random bytes with the first shared secret
	EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, ss1, iv);
        EVP_EncryptUpdate(ctx, et, &len, rand1 + (i * ct_block), ct_block);
        EVP_EncryptFinal_ex(ctx, et, &len);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, ct_block, (void*) tag);

	// Format the block
        for (j = 0; j < ct_block; j++) {
	    final[j] = et[j];
	    final[ct_block + j] = tag[j];
	}

        sendto(sockfd, (const unsigned char *)final, full_block, MSG_CONFIRM, (const struct sockaddr *) &servaddr, sizeof(servaddr)); // Step 12
    }
    
    // Listen for random bytes from the server
    for (i = 0; i < full_block / ct_block; i++) {

        n = recvfrom(sockfd, (unsigned char *)rec, full_block, MSG_WAITALL, (struct sockaddr *) &servaddr, &len); // Step 15
	rec[n] = '\0';

	for (j = 0; j < ct_block; j++) tag[j] = rec[ct_block + j]; // Set the authentication tag

	// Step 16
	// Symmetrically decrypt the random bytes with the second shared secret
	EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, ss2, iv);
	EVP_DecryptUpdate(ctx, et, &len, rec, ct_block);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, ct_block, (void*)tag);
	n = EVP_DecryptFinal_ex(ctx, et, &len);
	assert(n == 1); // Authenticate the ciphertext

	for (j = 0; j < ct_block; j++) rand2[(i * ct_block) + j] = et[j]; // Store the random bytes
    }

    // Compare the two strings of random bytes to ensure they match
    for (i = 0; i < full_block; i++) assert(rand1[i] == rand2[i]); // Step 17

    // Listen for random bytes from the server
    for (i = 0; i < full_block / ct_block; i++) {

        n = recvfrom(sockfd, (unsigned char *)rec, full_block, MSG_WAITALL, (struct sockaddr *) &servaddr, &len); // Step 20
	rec[n] = '\0';

	for (j = 0; j < ct_block; j++) tag[j] = rec[ct_block + j]; // Set the authentication tag

	// Step 21
	// Symmetrically decrypt the random bytes with the first shared secret
	EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, ss1, iv);
	EVP_DecryptUpdate(ctx, et, &len, rec, ct_block);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, ct_block, (void*)tag);
	n = EVP_DecryptFinal_ex(ctx, et, &len);
	assert(n == 1); // Authenticate the ciphertext

	for (j = 0; j < ct_block; j++) rand2[(i * ct_block) + j] = et[j]; // Store the random bytes
    }

    // Send random bytes back to the server
    for (i = 0; i < full_block / ct_block; i++) {

        // Step 22
	// Symmetrically encrypt the random bytes with the second shared secret	    
	EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, ss2, iv);
        EVP_EncryptUpdate(ctx, et, &len, rand2 + (i * ct_block), ct_block);
        EVP_EncryptFinal_ex(ctx, et, &len);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, ct_block, (void*) tag);

	// Format the block
        for (j = 0; j < ct_block; j++) {
	    final[j] = et[j];
	    final[ct_block + j] = tag[j];
	}

        sendto(sockfd, (const unsigned char *)final, full_block, MSG_CONFIRM, (const struct sockaddr *) &servaddr, sizeof(servaddr)); // Step 23
    }

    free(rec);
    free(entropy);
    free(personal);
    free(spk);
    free(ct);
    free(ss1);
    free(cpk);
    free(sk);
    free(ss2);
    free(rand1);
    free(rand2);

    free(iv);
    free(tag);
    free(et);
    free(final);
    EVP_CIPHER_CTX_free(ctx);

    end = clock();
    printf("Cycles: %lu\n", end - start);
    printf("Cycles Per Second: %lu\n", CLOCKS_PER_SEC);

    close(sockfd); // Close the socket
    return 0;
}
