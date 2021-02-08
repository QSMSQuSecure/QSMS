/*
 * client.c
 *
 * Chris Cap
 * Copyright 2021 by QuSecure, Inc.
 */

// Load standard libraries
#include <time.h>
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

#define PORT 8443

int main() { 
    
    int sockfd;  // Socket file descriptor
    struct sockaddr_in server_ipa; // Server IP address
    struct sockaddr_in peer_ipa;

    int cipher_block; // Length of the AES cipher block
    int key_block; // Length of the AES key
    int hash_block; // Length of the SHA3 output
    int max_block; // Maximum buffer length
    
    unsigned char *buf; // TCP buffer
    unsigned char *entropy; // Entropy input to randombytes_init()
    unsigned char *personal; // Personalization string input to randombytes_init()
    unsigned char *server_pk; // Server KEM public key
    unsigned char *ct; // KEM ciphertext
    unsigned char *ss1; // First shared secret
    unsigned char *client_pk; // Client KEM public key
    unsigned char *client_sk; // Client KEM secret key
    unsigned char *ss2; // Second shared secret
    unsigned char *rand1; // Sent string of random bits
    unsigned char *rand2; // Received string of random bits
    unsigned char *rand3; // Received string of random bits

    unsigned char *iv; // AES initialization vector
    unsigned char *tag1; // SHA3 authentication tag calculated
    unsigned char *tag2; // SHA3 authentication tag received
    unsigned char *et; // Encrypted/decrypted text
    unsigned char *input; // Input buffer
    EVP_CIPHER_CTX *sctx; // AES context
    EVP_MD_CTX *hctx; // SHA3 context

    unsigned char *session;
    char *message;
    int mlen;
        
    FILE *in; // Server KEM public key storage
    
    int i; // Loop counter
    int len; // Length variable

    clock_t start; // Time of program start
    clock_t end; // Time of program end

    // Initialize constants
    cipher_block = 16;
    key_block = 32;
    hash_block = 48;
    max_block = CRYPTO_CIPHERTEXTBYTES + cipher_block + CRYPTO_PUBLICKEYBYTES + hash_block;

    // Initialize variables used by TCP
    buf = calloc(max_block, 1);
    
    // Initialize variables used by KEM
    entropy = calloc(hash_block, 1);
    personal = calloc(hash_block, 1);
    client_pk = calloc(CRYPTO_PUBLICKEYBYTES, 1);
    client_sk = calloc(CRYPTO_SECRETKEYBYTES, 1);
    ct = calloc(CRYPTO_CIPHERTEXTBYTES, 1);
    ss1 = calloc(CRYPTO_BYTES, 1);
    server_pk = calloc(CRYPTO_PUBLICKEYBYTES, 1);
    ss2 = calloc(CRYPTO_BYTES, 1);
    rand1 = calloc(key_block, 1);
    rand2 = calloc(key_block, 1);
    rand3 = calloc(key_block, 1);
    
    // Initialize variables used by AES and SHA3
    iv = calloc(cipher_block, 1);
    tag1 = calloc(hash_block, 1);
    tag2 = calloc(hash_block, 1);
    et = calloc(max_block, 1);
    input = calloc(max_block, 1);
    sctx = EVP_CIPHER_CTX_new();
    hctx = EVP_MD_CTX_new();

    session = calloc(key_block, 1);
    message = calloc(80, 1);

    // Create socket file descriptor for TCP socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    assert(sockfd >= 0);

    // Initialize server address
    memset(&server_ipa, 0, sizeof(server_ipa));
    server_ipa.sin_family = AF_INET;
    server_ipa.sin_addr.s_addr = inet_addr("172.28.221.223"); // Change to match server
    server_ipa.sin_port = htons(PORT);
   
    // Connect to the TCP socket
    assert(connect(sockfd, (struct sockaddr *)&server_ipa, sizeof(server_ipa)) == 0);

    // Set entropy input and personalization string
    memset(entropy, 0x38, hash_block);
    memset(personal, 0xf9, hash_block);
    
    start = clock(); // Start timer

    randombytes_init(entropy, personal, 1); // Prepare the PRNG

    // Read server public key from file
    in = fopen("server.key", "r");
    fread(server_pk, 1, CRYPTO_PUBLICKEYBYTES, in);
    fclose(in);

    crypto_kem_keypair(client_pk, client_sk); // Generate client KEM keypair

    crypto_kem_enc(ct, ss1, server_pk); // Encapsulate the first shared secret
    
    // Use flag to demo and debug
    #ifdef DEBUG
        printf("Server Public Key: ");
        for (i = 0; i < CRYPTO_PUBLICKEYBYTES; i++) printf("%02x", server_pk[i]); printf("\n\n");
        printf("Shared Secret 1: ");
        for (i = 0; i < key_block; i++) printf("%02x", ss1[i]); printf("\n\n");
        printf("Client Public Key: ");
        for (i = 0; i < CRYPTO_PUBLICKEYBYTES; i++) printf("%02x", client_pk[i]); printf("\n\n");
    #endif

    randombytes(iv, cipher_block); // Set initialization vector
    
    // Format the input buffer for SHA-3
    memcpy(input, ct, CRYPTO_CIPHERTEXTBYTES);
    memcpy(input + CRYPTO_CIPHERTEXTBYTES, iv, cipher_block);
    memcpy(input + CRYPTO_CIPHERTEXTBYTES + cipher_block, client_pk, CRYPTO_PUBLICKEYBYTES);

    // Hash the ciphertext, initialization vector, client public key, and MAC address
    assert(EVP_DigestInit_ex(hctx, EVP_sha3_384(), NULL));
    assert(EVP_DigestUpdate(hctx, input, CRYPTO_CIPHERTEXTBYTES + cipher_block + CRYPTO_PUBLICKEYBYTES));
    assert(EVP_DigestFinal_ex(hctx, tag1, &len));

    // Format the input buffer for AES
    memcpy(input, client_pk, CRYPTO_PUBLICKEYBYTES);
    memcpy(input + CRYPTO_PUBLICKEYBYTES, tag1, hash_block);

    // Symmetrically encrypt the client public key, MAC address, and authentication tag using the first shared secret
    assert(EVP_EncryptInit_ex(sctx, EVP_aes_256_ctr(), NULL, ss1, iv));
    assert(EVP_EncryptUpdate(sctx, et, &len, input, CRYPTO_PUBLICKEYBYTES + hash_block));
    assert(EVP_EncryptFinal_ex(sctx, et, &len));
     
    // Format the TCP buffer
    memcpy(buf, ct, CRYPTO_CIPHERTEXTBYTES);
    memcpy(buf + CRYPTO_CIPHERTEXTBYTES, iv, cipher_block);
    memcpy(buf + CRYPTO_CIPHERTEXTBYTES + cipher_block, et, CRYPTO_PUBLICKEYBYTES + hash_block);

    write(sockfd, (const unsigned char *)buf, max_block); // Send over TCP

    read(sockfd, (unsigned char *)buf, cipher_block + CRYPTO_CIPHERTEXTBYTES + hash_block); // Receive over TCP

    memcpy(iv, buf, cipher_block); // Store initialization vector

    // Format the input buffer for AES
    memcpy(input, buf + cipher_block, CRYPTO_CIPHERTEXTBYTES + hash_block);

    // Symmetrically decrypt the ciphertext and authentication tag using the first shared secret
    assert(EVP_DecryptInit_ex(sctx, EVP_aes_256_ctr(), NULL, ss1, iv));
    assert(EVP_DecryptUpdate(sctx, et, &len, input, CRYPTO_CIPHERTEXTBYTES + hash_block));
    assert(EVP_DecryptFinal_ex(sctx, et, &len));

    // Store the ciphertext and authentiction tag
    memcpy(ct, et, CRYPTO_CIPHERTEXTBYTES);
    memcpy(tag1, et + CRYPTO_CIPHERTEXTBYTES, hash_block);

    // Format the input buffer for SHA-3
    memcpy(input, iv, cipher_block);
    memcpy(input + cipher_block, ct, CRYPTO_CIPHERTEXTBYTES);

    // Hash the initialization vector and ciphertext
    assert(EVP_DigestInit_ex(hctx, EVP_sha3_384(), NULL));
    assert(EVP_DigestUpdate(hctx, input, cipher_block + CRYPTO_CIPHERTEXTBYTES));
    assert(EVP_DigestFinal_ex(hctx, tag2, &len));

    assert(memcmp(tag1, tag2, hash_block) == 0); // Authenticate the ciphertext

    crypto_kem_dec(ss2, ct, client_sk); // Decapsulate the second shared secret

    // Use flag to demo and debug
    #ifdef DEBUG
        printf("Shared Secret 2: ");
        for (i = 0; i < key_block; i++) printf("%02x", ss2[i]); printf("\n\n");
    #endif
    
    randombytes(rand1, key_block); // Generate random bytes for authentication

    randombytes(iv, cipher_block); // Set initialization vector

    // Format the input buffer for SHA-3
    memcpy(input, iv, cipher_block);
    memcpy(input + cipher_block, rand1, cipher_block + key_block);

    // Hash the initialization vector and random bytes
    assert(EVP_DigestInit_ex(hctx, EVP_sha3_384(), NULL));
    assert(EVP_DigestUpdate(hctx, input, cipher_block + key_block));
    assert(EVP_DigestFinal_ex(hctx, tag1, &len));

    // Format the input buffer for AES
    memcpy(input, rand1, key_block);
    memcpy(input + key_block, tag1, hash_block);

    // Symmetrically encrypt the random bytes and the authentication tag using the first shared secret
    assert(EVP_EncryptInit_ex(sctx, EVP_aes_256_ctr(), NULL, ss1, iv));
    assert(EVP_EncryptUpdate(sctx, et, &len, input, key_block + hash_block));
    assert(EVP_EncryptFinal_ex(sctx, et, &len)); 
    
    // Format the TCP buffer
    memcpy(buf, iv, cipher_block);
    memcpy(buf + cipher_block, et, key_block + hash_block);

    write(sockfd, (const unsigned char *)buf, cipher_block + key_block + hash_block); // Send over TCP
    
    read(sockfd, (unsigned char *)buf, cipher_block + key_block + key_block + hash_block); // Receive over TCP

    memcpy(iv, buf, cipher_block); // Store initialization vector

    // Format the input buffer
    memcpy(input, buf + cipher_block, key_block + key_block + hash_block);

    // Symmetrically decrypt two strings of random bytes and the authentication tag using the first shared secret
    assert(EVP_DecryptInit_ex(sctx, EVP_aes_256_ctr(), NULL, ss2, iv));
    assert(EVP_DecryptUpdate(sctx, et, &len, input, key_block + key_block + hash_block));
    assert(EVP_DecryptFinal_ex(sctx, et, &len));

    // Store the two strings and the authentication tag
    memcpy(rand2, et, key_block);
    memcpy(rand3, et + key_block, key_block);
    memcpy(tag1, et + key_block + key_block, hash_block);

    // Format the input buffer for SHA-3
    memcpy(input, iv, cipher_block);
    memcpy(input + cipher_block, rand2, key_block);
    memcpy(input + cipher_block + key_block, rand3, key_block);

    // Hash the initialization vector and two strings of random bytes
    assert(EVP_DigestInit_ex(hctx, EVP_sha3_384(), NULL));
    assert(EVP_DigestUpdate(hctx, input, cipher_block + key_block + key_block));
    assert(EVP_DigestFinal_ex(hctx, tag2, &len));

    assert(memcmp(tag1, tag2, hash_block) == 0); // Authenticate the strings

    // Use flag to demo and debug
    #ifdef DEBUG
        printf("Random Sent: ");
        for (i = 0; i < key_block; i++) printf("%02x", rand1[i]); printf("\n\n");
        printf("Random Received: ");
        for (i = 0; i < key_block; i++) printf("%02x", rand2[i]); printf("\n\n");
    #endif

    assert(memcmp(rand1, rand2, key_block) == 0); // Authenticate the server by comparing the two strings
    
    randombytes(iv, cipher_block); // Set intialization vector

    // Format the input buffer for SHA-3
    memcpy(input, iv, cipher_block);
    memcpy(input + cipher_block, rand3, key_block);

    // Hash the second string of random bytes
    assert(EVP_DigestInit_ex(hctx, EVP_sha3_384(), NULL));
    assert(EVP_DigestUpdate(hctx, input, cipher_block + key_block));
    assert(EVP_DigestFinal_ex(hctx, tag1, &len));
    
    // Format the input buffer for AES
    memcpy(input, rand3, key_block);
    memcpy(input + key_block, tag1, hash_block);

    // Symmetrically encrypt the random bytes and the authentication tag using the first shared secret	    
    assert(EVP_EncryptInit_ex(sctx, EVP_aes_256_ctr(), NULL, ss1, iv));
    assert(EVP_EncryptUpdate(sctx, et, &len, input, key_block + hash_block));
    assert(EVP_EncryptFinal_ex(sctx, et, &len));

    // Format the TCP buffer
    memcpy(buf, iv, cipher_block);
    memcpy(buf + cipher_block, et, key_block + hash_block);

    write(sockfd, (const unsigned char *)buf, cipher_block + key_block + hash_block); // Send over TCP

    read(sockfd, (unsigned char *)buf, cipher_block + key_block + hash_block);

    memcpy(iv, buf, cipher_block);

    memcpy(input, buf + cipher_block, key_block + hash_block);

    assert(EVP_DecryptInit_ex(sctx, EVP_aes_256_ctr(), NULL, ss1, iv));
    assert(EVP_DecryptUpdate(sctx, et, &len, input, key_block + hash_block));
    assert(EVP_DecryptFinal(sctx, et, &len));

    memcpy(session, et, key_block);
    memcpy(tag1, et + key_block, hash_block);

    memcpy(input, iv, cipher_block);
    memcpy(input + cipher_block, session, key_block);
    
    assert(EVP_DigestInit_ex(hctx, EVP_sha3_384(), NULL));
    assert(EVP_DigestUpdate(hctx, input, cipher_block + key_block));
    assert(EVP_DigestFinal(hctx, tag2, &len));

    assert(memcmp(tag1, tag2, hash_block) == 0);

    close(sockfd);
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    assert(sockfd >= 0);

    // Initialize server address
    memset(&peer_ipa, 0, sizeof(peer_ipa));
    peer_ipa.sin_family = AF_INET;
    peer_ipa.sin_addr.s_addr = inet_addr("172.28.209.139"); // Change to match peer
    peer_ipa.sin_port = htons(PORT);
   
    // Connect to the TCP socket
    assert(connect(sockfd, (struct sockaddr *)&peer_ipa, sizeof(peer_ipa)) == 0);

    message = "This message was sent over a post-quantum encrypted tunnel created by QuSecure.";
    mlen = strlen(message);

    randombytes(iv, cipher_block);

    memcpy(input, iv, cipher_block);
    memcpy(input + cipher_block, message, mlen + 1);

    assert(EVP_DigestInit_ex(hctx, EVP_sha3_384(), NULL));
    assert(EVP_DigestUpdate(hctx, input, cipher_block + mlen + 1));
    assert(EVP_DigestFinal_ex(hctx, tag1, &len));

    memcpy(input, message, mlen + 1);
    memcpy(input + mlen + 1, tag1, hash_block);

    assert(EVP_EncryptInit_ex(sctx, EVP_aes_256_ctr(), NULL, session, iv));
    assert(EVP_EncryptUpdate(sctx, et, &len, input, mlen + 1 + hash_block));
    assert(EVP_EncryptFinal_ex(sctx, et, &len));

    memcpy(buf, iv, cipher_block);
    memcpy(buf + cipher_block, et, mlen + 1 + hash_block);

    write(sockfd, (const unsigned char *)buf, cipher_block + mlen + 1 + hash_block);

    end = clock(); // Stop timer
    printf("Time: %f seconds\n", ((float)end - (float)start) / (float)CLOCKS_PER_SEC); // Print time
    
    // Free pointers used by KEM
    free(buf);
    free(entropy);
    free(personal);
    free(server_pk);
    free(ct);
    free(ss1);
    free(client_pk);
    free(client_sk);
    free(ss2);
    free(rand1);
    free(rand2);
    free(rand3);

    // Free pointers used by AES and SHA-3
    free(iv);
    free(tag1);
    free(tag2);
    free(et);
    free(input);
    EVP_CIPHER_CTX_free(sctx);
    EVP_MD_CTX_free(hctx);
    free(session);

    close(sockfd); // Close the socket
    return 0;
}
