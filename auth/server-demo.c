/* 
 * server.c
 *
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

#define PORT 8443 

int main() { 

    int sockfd; // Socket file descriptor
    int connfd1; // Connection file descriptor
    int connfd2;
    struct sockaddr_in client_ipa; // Client IP address
    struct sockaddr_in peer_ipa;

    int cipher_block; // Length of the AES cipher block
    int key_block; // Length of the AES key
    int hash_block; // Length of the SHA3 output
    int max_block;  // Maximum buffer length

    unsigned char *buf; // TCP buffer
    unsigned char *entropy; // Entropy input to randombytes_init()
    unsigned char *personal; // Personalization string input to randombytes_init()
    unsigned char *server_pk; // Server KEM public key
    unsigned char *server_sk; // Server KEM secret key
    unsigned char *ct; // KEM ciphertext
    unsigned char *css1; // First shared secret
    unsigned char *client_pk; // Client KEM public key
    unsigned char *css2; // Second shared secret
    unsigned char *rand1; // Sent string of random bits
    unsigned char *rand2; // Received string of random bits
    unsigned char *pss1; // First shared secret
    unsigned char *peer_pk; // Client KEM public key
    unsigned char *pss2; // Second shared secret

    unsigned char *iv; // Initialization vector
    unsigned char *tag1; // SHA3 authentication tag calculated
    unsigned char *tag2; // SHA3 authentication tag received
    unsigned char *et; // Encrypted/decrypted text
    unsigned char *input; // Input buffer
    unsigned char *uid1; // Unique identifier
    unsigned char *uid2;
    EVP_CIPHER_CTX *sctx; // AES context
    EVP_MD_CTX *hctx; // SHA3 context

    unsigned char *session;

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
           
    // Initialize variables used by KEM
    buf = calloc(max_block, 1);
    entropy = calloc(hash_block, 1);
    personal = calloc(hash_block, 1);
    client_pk = calloc(CRYPTO_PUBLICKEYBYTES, 1);
    ct = calloc(CRYPTO_CIPHERTEXTBYTES, 1);
    css1 = calloc(CRYPTO_BYTES, 1);
    server_pk = calloc(CRYPTO_PUBLICKEYBYTES, 1);
    server_sk = calloc(CRYPTO_SECRETKEYBYTES, 1);
    css2 = calloc(CRYPTO_BYTES, 1);
    rand1 = calloc(key_block, 1);
    rand2 = calloc(key_block, 1);
    peer_pk = calloc(CRYPTO_PUBLICKEYBYTES, 1);
    pss1 = calloc(key_block, 1);
    pss2 = calloc(key_block, 1);

    // Initialize variables used by AES and SHA3
    iv = calloc(cipher_block, 1);
    tag1 = calloc(hash_block, 1);
    tag2 = calloc(hash_block, 1);
    et = calloc(max_block, 1);
    input = calloc(max_block, 1);
    uid1 = calloc(hash_block, 1);
    uid2 = calloc(hash_block, 1);
    sctx = EVP_CIPHER_CTX_new();
    hctx = EVP_MD_CTX_new();

    session = calloc(key_block, 1);

    // Create socket file descriptor
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    assert(sockfd >= 0);

    // Initialize client address
    memset(&client_ipa, 0, sizeof(client_ipa)); 
    client_ipa.sin_family = AF_INET; // IPv4 
    client_ipa.sin_addr.s_addr = INADDR_ANY; 
    client_ipa.sin_port = htons(PORT); 
    
    // Bind the socket with the client address 
    assert(bind(sockfd, (const struct sockaddr *)&client_ipa, sizeof(client_ipa)) == 0);

    // Listen for a client connection
    assert(listen(sockfd, PORT) == 0);

    // Accept the client connection
    len = sizeof(client_ipa);
    connfd1 = accept(sockfd, (struct sockaddr *)&client_ipa, &len);
    assert(connfd1 >= 0);

    // Set the entropy input and personalization string
    memset(entropy, (int)0x4f, hash_block);
    memset(personal, (int)0xc3, hash_block);

    start = clock(); // Start timer
    
    randombytes_init(entropy, personal, 1); // Prepare the PRNG

    crypto_kem_keypair(server_pk, server_sk); // Generate server KEM keypair

    // Store the server KEM public key to file
    in = fopen("server.key", "w");
    fwrite(server_pk, 1, CRYPTO_PUBLICKEYBYTES, in);
    fclose(in);

    read(connfd1, (unsigned char *)buf, max_block); // Receive over TCP
    
    memcpy(ct, buf, CRYPTO_CIPHERTEXTBYTES); // Store ciphertext variable

    crypto_kem_dec(css1, ct, server_sk); // Decapsulate the first shared secret

    memcpy(iv, buf + CRYPTO_CIPHERTEXTBYTES, cipher_block); // Store initialization vector

    // Format the input buffer for AES
    memcpy(input, buf + CRYPTO_CIPHERTEXTBYTES + cipher_block, CRYPTO_PUBLICKEYBYTES + hash_block);

    // Symmetrically decrypt the public key, MAC address, and authentication tag using the first shared secret
    assert(EVP_DecryptInit_ex(sctx, EVP_aes_256_ctr(), NULL, css1, iv));
    assert(EVP_DecryptUpdate(sctx, et, &len, input, CRYPTO_PUBLICKEYBYTES + hash_block));
    assert(EVP_DecryptFinal_ex(sctx, et, &len));

    // Store the client public key and authentication tag, and format the input buffer for SHA-3
    memcpy(input, ct, CRYPTO_CIPHERTEXTBYTES);
    memcpy(input + CRYPTO_CIPHERTEXTBYTES, iv, cipher_block);
    memcpy(client_pk, et, CRYPTO_PUBLICKEYBYTES);
    memcpy(tag1, et + CRYPTO_PUBLICKEYBYTES, hash_block);
    memcpy(input + CRYPTO_CIPHERTEXTBYTES + cipher_block, client_pk, CRYPTO_PUBLICKEYBYTES);

    // Hash the ciphertext, initialization vector, and public key
    assert(EVP_DigestInit_ex(hctx, EVP_sha3_384(), NULL));
    assert(EVP_DigestUpdate(hctx, input, CRYPTO_CIPHERTEXTBYTES + cipher_block + CRYPTO_PUBLICKEYBYTES));
    assert(EVP_DigestFinal_ex(hctx, tag2, &len));

    assert(memcmp(tag1, tag2, hash_block) == 0); // Authenticate the ciphertext and public key
 
    // Use flag to demo and debug
    #ifdef DEBUG
        printf("Server Public Key: ");
        for (i = 0; i < CRYPTO_PUBLICKEYBYTES; i++) printf("%02x", server_pk[i]); printf("\n\n");
        printf("Shared Secret 1: ");
        for (i = 0; i < key_block; i++) printf("%02x", css1[i]); printf("\n\n");
    #endif
 
    // Hash the client public key
    assert(EVP_DigestInit_ex(hctx, EVP_sha3_384(), NULL));
    assert(EVP_DigestUpdate(hctx, client_pk, CRYPTO_PUBLICKEYBYTES));
    assert(EVP_DigestFinal_ex(hctx, uid1, &len));

    assert(memcmp(uid1, uid1, hash_block) == 0); // Database placeholder

    crypto_kem_enc(ct, css2, client_pk); // Encapsulate the second shared secret
    
    randombytes(iv, cipher_block); // Set intialization vector

    // Format the input buffer for SHA-3
    memcpy(input, iv, cipher_block);
    memcpy(input + cipher_block, ct, CRYPTO_CIPHERTEXTBYTES);

    // Hash the initialization vector and ciphertext
    assert(EVP_DigestInit_ex(hctx, EVP_sha3_384(), NULL));
    assert(EVP_DigestUpdate(hctx, input, cipher_block + CRYPTO_CIPHERTEXTBYTES));
    assert(EVP_DigestFinal_ex(hctx, tag1, &len));

    // Format the input buffer for AES
    memcpy(input, ct, CRYPTO_CIPHERTEXTBYTES);
    memcpy(input + CRYPTO_CIPHERTEXTBYTES, tag1, hash_block);

    // Use flag to demo and debug
    #ifdef DEBUG
        printf("Client Public Key: ");
        for (i = 0; i < CRYPTO_PUBLICKEYBYTES; i++) printf("%02x", client_pk[i]); printf("\n\n");
        printf("Shared Secret 2: ");
        for (i = 0; i < key_block; i++) printf("%02x", css2[i]); printf("\n\n");
    #endif

    // Symmetrically encrypt the ciphertext and authentication tag with the first shared secret
    assert(EVP_EncryptInit_ex(sctx, EVP_aes_256_ctr(), NULL, css1, iv));
    assert(EVP_EncryptUpdate(sctx, et, &len, input, CRYPTO_CIPHERTEXTBYTES + hash_block));
    assert(EVP_EncryptFinal_ex(sctx, et, &len));

    memcpy(buf, iv, cipher_block);
    memcpy(buf + cipher_block, et, CRYPTO_CIPHERTEXTBYTES + hash_block); // Copy encrypted data to TCP buffer

    write(connfd1, (const unsigned char *)buf, cipher_block + CRYPTO_CIPHERTEXTBYTES + hash_block); // Send over TCP

    read(connfd1, (unsigned char *)buf, cipher_block + key_block + hash_block); // Receive over TCP

    memcpy(iv, buf, cipher_block); // Set initialization vector

    // Format the input buffer for AES
    memcpy(input, buf + cipher_block, key_block + hash_block); 

    // Symmetrically decrypt the random bytes and the authentication tag using the first shared secret
    assert(EVP_DecryptInit_ex(sctx, EVP_aes_256_ctr(), NULL, css1, iv));
    assert(EVP_DecryptUpdate(sctx, et, &len, input, key_block + hash_block));
    assert(EVP_DecryptFinal_ex(sctx, et, &len));

    // Store the string of random bytes and the authentication tag
    memcpy(rand2, et, key_block);
    memcpy(tag1, et + key_block, hash_block);

    // Format input buffer for SHA-3
    memcpy(input, iv, cipher_block);
    memcpy(input + cipher_block, rand2, key_block);

    // Hash the initalization vector and random bytes
    assert(EVP_DigestInit_ex(hctx, EVP_sha3_384(), NULL));
    assert(EVP_DigestUpdate(hctx, input, cipher_block + key_block));
    assert(EVP_DigestFinal_ex(hctx, tag2, &len));

    assert(memcmp(tag1, tag2, hash_block) == 0); // Authenticate the random bytes
    
    randombytes(rand1, key_block); // Generate random bytes for authentication

    randombytes(iv, cipher_block);

    // Format the input buffer for SHA-3
    memcpy(input, iv, cipher_block);
    memcpy(input + cipher_block, rand2, key_block);
    memcpy(input + cipher_block + key_block, rand1, key_block);
    
    // Hash the initialization vector and two strings of random bytes
    assert(EVP_DigestInit_ex(hctx, EVP_sha3_384(), NULL));
    assert(EVP_DigestUpdate(hctx, input, cipher_block + key_block + key_block));
    assert(EVP_DigestFinal_ex(hctx, tag1, &len));

    // Format the input buffer for AES
    memcpy(input, rand2, key_block);
    memcpy(input + key_block, rand1, key_block);
    memcpy(input + key_block + key_block, tag1, hash_block);

    // Symmetrically encrypt the two strings and the authentication tag using the second shared secret
    assert(EVP_EncryptInit_ex(sctx, EVP_aes_256_ctr(), NULL, css2, iv));
    assert(EVP_EncryptUpdate(sctx, et, &len, input, key_block + key_block + hash_block));
    assert(EVP_EncryptFinal_ex(sctx, et, &len));

    // Format the TCP buffer
    memcpy(buf, iv, cipher_block);
    memcpy(buf + cipher_block, et, key_block + key_block + hash_block);

    write(connfd1, (const unsigned char *)buf, cipher_block + key_block + key_block + hash_block); // Send over TCP

    read(connfd1, (unsigned char *)buf, cipher_block + key_block + hash_block); // Receive over TCP

    memcpy(iv, buf, cipher_block); // Set initialization vector

    // Format the input buffer for AES
    memcpy(input, buf + cipher_block, key_block + hash_block);

    // Symmetrically decrypt the random bytes and authentication tag using the first shared secret
    assert(EVP_DecryptInit_ex(sctx, EVP_aes_256_ctr(), NULL, css1, iv));
    assert(EVP_DecryptUpdate(sctx, et, &len, input, key_block + hash_block));
    assert(EVP_DecryptFinal_ex(sctx, et, &len));    

    // Store the random bytes and the authentication tag
    memcpy(rand2, et, key_block);
    memcpy(tag1, et + key_block, hash_block);

    // Format the input buffer for SHA-3
    memcpy(input, iv, cipher_block);
    memcpy(input + cipher_block, rand2, key_block);

    // Hash the initialization vector and random bytes
    assert(EVP_DigestInit_ex(hctx, EVP_sha3_384(), NULL));
    assert(EVP_DigestUpdate(hctx, input, cipher_block + key_block));
    assert(EVP_DigestFinal_ex(hctx, tag2, &len));

    assert(memcmp(tag1, tag2, hash_block) == 0); // Authenticate the randombytes

    // Use flag to demo and debug
    #ifdef DEBUG
        printf("Random Sent: ");
        for (i = 0; i < key_block; i++) printf("%02x", rand1[i]); printf("\n\n");
        printf("Random Received: ");
        for (i = 0; i < key_block; i++) printf("%02x", rand2[i]); printf("\n\n");
    #endif
    
    assert(memcmp(rand1, rand2, key_block) == 0); // Authenticate the client by comparing the two strings
    
    end = clock(); // Stop timer
    printf("Time: %f seconds\n", ((float)end - (float)start) / (float)CLOCKS_PER_SEC); // Print time

    // Accept the client connection
    len = sizeof(peer_ipa);
    connfd2 = accept(sockfd, (struct sockaddr *)&peer_ipa, &len);
    assert(connfd2 >= 0);

    start = clock(); // Start timer
    
    read(connfd2, (unsigned char *)buf, max_block); // Receive over TCP
    
    memcpy(ct, buf, CRYPTO_CIPHERTEXTBYTES); // Store ciphertext variable

    crypto_kem_dec(pss1, ct, server_sk); // Decapsulate the first shared secret

    memcpy(iv, buf + CRYPTO_CIPHERTEXTBYTES, cipher_block); // Store initialization vector

    // Format the input buffer for AES
    memcpy(input, buf + CRYPTO_CIPHERTEXTBYTES + cipher_block, CRYPTO_PUBLICKEYBYTES + hash_block);

    // Symmetrically decrypt the public key, MAC address, and authentication tag using the first shared secret
    assert(EVP_DecryptInit_ex(sctx, EVP_aes_256_ctr(), NULL, pss1, iv));
    assert(EVP_DecryptUpdate(sctx, et, &len, input, CRYPTO_PUBLICKEYBYTES + hash_block));
    assert(EVP_DecryptFinal_ex(sctx, et, &len));

    // Store the client public key and authentication tag, and format the input buffer for SHA-3
    memcpy(input, ct, CRYPTO_CIPHERTEXTBYTES);
    memcpy(input + CRYPTO_CIPHERTEXTBYTES, iv, cipher_block);
    memcpy(peer_pk, et, CRYPTO_PUBLICKEYBYTES);
    memcpy(tag1, et + CRYPTO_PUBLICKEYBYTES, hash_block);
    memcpy(input + CRYPTO_CIPHERTEXTBYTES + cipher_block, peer_pk, CRYPTO_PUBLICKEYBYTES);

    // Hash the ciphertext, initialization vector, and public key
    assert(EVP_DigestInit_ex(hctx, EVP_sha3_384(), NULL));
    assert(EVP_DigestUpdate(hctx, input, CRYPTO_CIPHERTEXTBYTES + cipher_block + CRYPTO_PUBLICKEYBYTES));
    assert(EVP_DigestFinal_ex(hctx, tag2, &len));

    assert(memcmp(tag1, tag2, hash_block) == 0); // Authenticate the ciphertext and public key
 
    // Use flag to demo and debug
    #ifdef DEBUG
        printf("Server Public Key: ");
        for (i = 0; i < CRYPTO_PUBLICKEYBYTES; i++) printf("%02x", server_pk[i]); printf("\n\n");
        printf("Shared Secret 1: ");
        for (i = 0; i < key_block; i++) printf("%02x", pss1[i]); printf("\n\n");
    #endif
 
    // Hash the peer public key
    assert(EVP_DigestInit_ex(hctx, EVP_sha3_384(), NULL));
    assert(EVP_DigestUpdate(hctx, peer_pk, CRYPTO_PUBLICKEYBYTES));
    assert(EVP_DigestFinal_ex(hctx, uid2, &len));

    assert(memcmp(uid2, uid2, hash_block) == 0); // Database placeholder

    crypto_kem_enc(ct, pss2, peer_pk); // Encapsulate the second shared secret
    
    randombytes(iv, cipher_block); // Set intialization vector

    // Format the input buffer for SHA-3
    memcpy(input, iv, cipher_block);
    memcpy(input + cipher_block, ct, CRYPTO_CIPHERTEXTBYTES);

    // Hash the initialization vector and ciphertext
    assert(EVP_DigestInit_ex(hctx, EVP_sha3_384(), NULL));
    assert(EVP_DigestUpdate(hctx, input, cipher_block + CRYPTO_CIPHERTEXTBYTES));
    assert(EVP_DigestFinal_ex(hctx, tag1, &len));

    // Format the input buffer for AES
    memcpy(input, ct, CRYPTO_CIPHERTEXTBYTES);
    memcpy(input + CRYPTO_CIPHERTEXTBYTES, tag1, hash_block);

    // Use flag to demo and debug
    #ifdef DEBUG
        printf("Peer Public Key: ");
        for (i = 0; i < CRYPTO_PUBLICKEYBYTES; i++) printf("%02x", peer_pk[i]); printf("\n\n");
        printf("Shared Secret 2: ");
        for (i = 0; i < key_block; i++) printf("%02x", pss2[i]); printf("\n\n");
    #endif

    // Symmetrically encrypt the ciphertext and authentication tag with the first shared secret
    assert(EVP_EncryptInit_ex(sctx, EVP_aes_256_ctr(), NULL, pss1, iv));
    assert(EVP_EncryptUpdate(sctx, et, &len, input, CRYPTO_CIPHERTEXTBYTES + hash_block));
    assert(EVP_EncryptFinal_ex(sctx, et, &len));

    memcpy(buf, iv, cipher_block);
    memcpy(buf + cipher_block, et, CRYPTO_CIPHERTEXTBYTES + hash_block); // Copy encrypted data to TCP buffer

    write(connfd2, (const unsigned char *)buf, cipher_block + CRYPTO_CIPHERTEXTBYTES + hash_block); // Send over TCP

    read(connfd2, (unsigned char *)buf, cipher_block + key_block + hash_block); // Receive over TCP

    memcpy(iv, buf, cipher_block); // Set initialization vector

    // Format the input buffer for AES
    memcpy(input, buf + cipher_block, key_block + hash_block); 

    // Symmetrically decrypt the random bytes and the authentication tag using the first shared secret
    assert(EVP_DecryptInit_ex(sctx, EVP_aes_256_ctr(), NULL, pss1, iv));
    assert(EVP_DecryptUpdate(sctx, et, &len, input, key_block + hash_block));
    assert(EVP_DecryptFinal_ex(sctx, et, &len));

    // Store the string of random bytes and the authentication tag
    memcpy(rand2, et, key_block);
    memcpy(tag1, et + key_block, hash_block);

    // Format input buffer for SHA-3
    memcpy(input, iv, cipher_block);
    memcpy(input + cipher_block, rand2, key_block);

    // Hash the initalization vector and random bytes
    assert(EVP_DigestInit_ex(hctx, EVP_sha3_384(), NULL));
    assert(EVP_DigestUpdate(hctx, input, cipher_block + key_block));
    assert(EVP_DigestFinal_ex(hctx, tag2, &len));

    assert(memcmp(tag1, tag2, hash_block) == 0); // Authenticate the random bytes
    
    randombytes(rand1, key_block); // Generate random bytes for authentication

    randombytes(iv, cipher_block);

    // Format the input buffer for SHA-3
    memcpy(input, iv, cipher_block);
    memcpy(input + cipher_block, rand2, key_block);
    memcpy(input + cipher_block + key_block, rand1, key_block);
    
    // Hash the initialization vector and two strings of random bytes
    assert(EVP_DigestInit_ex(hctx, EVP_sha3_384(), NULL));
    assert(EVP_DigestUpdate(hctx, input, cipher_block + key_block + key_block));
    assert(EVP_DigestFinal_ex(hctx, tag1, &len));

    // Format the input buffer for AES
    memcpy(input, rand2, key_block);
    memcpy(input + key_block, rand1, key_block);
    memcpy(input + key_block + key_block, tag1, hash_block);

    // Symmetrically encrypt the two strings and the authentication tag using the second shared secret
    assert(EVP_EncryptInit_ex(sctx, EVP_aes_256_ctr(), NULL, pss2, iv));
    assert(EVP_EncryptUpdate(sctx, et, &len, input, key_block + key_block + hash_block));
    assert(EVP_EncryptFinal_ex(sctx, et, &len));

    // Format the TCP buffer
    memcpy(buf, iv, cipher_block);
    memcpy(buf + cipher_block, et, key_block + key_block + hash_block);

    write(connfd2, (const unsigned char *)buf, cipher_block + key_block + key_block + hash_block); // Send over TCP

    read(connfd2, (unsigned char *)buf, cipher_block + key_block + hash_block); // Receive over TCP

    memcpy(iv, buf, cipher_block); // Set initialization vector

    // Format the input buffer for AES
    memcpy(input, buf + cipher_block, key_block + hash_block);

    // Symmetrically decrypt the random bytes and authentication tag using the first shared secret
    assert(EVP_DecryptInit_ex(sctx, EVP_aes_256_ctr(), NULL, pss1, iv));
    assert(EVP_DecryptUpdate(sctx, et, &len, input, key_block + hash_block));
    assert(EVP_DecryptFinal_ex(sctx, et, &len));    

    // Store the random bytes and the authentication tag
    memcpy(rand2, et, key_block);
    memcpy(tag1, et + key_block, hash_block);

    // Format the input buffer for SHA-3
    memcpy(input, iv, cipher_block);
    memcpy(input + cipher_block, rand2, key_block);

    // Hash the initialization vector and random bytes
    assert(EVP_DigestInit_ex(hctx, EVP_sha3_384(), NULL));
    assert(EVP_DigestUpdate(hctx, input, cipher_block + key_block));
    assert(EVP_DigestFinal_ex(hctx, tag2, &len));

    assert(memcmp(tag1, tag2, hash_block) == 0); // Authenticate the randombytes

    // Use flag to demo and debug
    #ifdef DEBUG
        printf("Random Sent: ");
        for (i = 0; i < key_block; i++) printf("%02x", rand1[i]); printf("\n\n");
        printf("Random Received: ");
        for (i = 0; i < key_block; i++) printf("%02x", rand2[i]); printf("\n\n");
    #endif
    
    assert(memcmp(rand1, rand2, key_block) == 0); // Authenticate the client by comparing the two strings
    
    end = clock(); // Stop timer
    printf("Time: %f seconds\n", ((float)end - (float)start) / (float)CLOCKS_PER_SEC); // Print time

    randombytes(session, key_block);

    randombytes(iv, cipher_block);

    // Format the input buffer for SHA-3
    memcpy(input, iv, cipher_block);
    memcpy(input + cipher_block, session, key_block);

    // Hash the initialization vector and random bytes
    assert(EVP_DigestInit_ex(hctx, EVP_sha3_384(), NULL));
    assert(EVP_DigestUpdate(hctx, input, cipher_block + key_block));
    assert(EVP_DigestFinal_ex(hctx, tag1, &len));

    // Format the input buffer for AES
    memcpy(input, session, key_block);
    memcpy(input + key_block, tag1, hash_block);

    // Symmetrically decrypt the random bytes and authentication tag using the first shared secret
    assert(EVP_EncryptInit_ex(sctx, EVP_aes_256_ctr(), NULL, css1, iv));
    assert(EVP_EncryptUpdate(sctx, et, &len, input, key_block + hash_block));
    assert(EVP_EncryptFinal_ex(sctx, et, &len));

    // Format TCP buffer
    memcpy(buf, iv, cipher_block);
    memcpy(buf + cipher_block, et, key_block + hash_block);

    write(connfd1, (const unsigned char *)buf, cipher_block + key_block + hash_block);

    randombytes(iv, cipher_block);

    // Format the input buffer for SHA-3
    memcpy(input, iv, cipher_block);
    memcpy(input + cipher_block, session, key_block);

    // Hash the initialization vector and random bytes
    assert(EVP_DigestInit_ex(hctx, EVP_sha3_384(), NULL));
    assert(EVP_DigestUpdate(hctx, input, cipher_block + key_block));
    assert(EVP_DigestFinal_ex(hctx, tag1, &len));

    // Format the input buffer for AES
    memcpy(input, session, key_block);
    memcpy(input + key_block, tag1, hash_block);

    // Symmetrically decrypt the random bytes and authentication tag using the first shared secret
    assert(EVP_EncryptInit_ex(sctx, EVP_aes_256_ctr(), NULL, pss1, iv));
    assert(EVP_EncryptUpdate(sctx, et, &len, input, key_block + hash_block));
    assert(EVP_EncryptFinal_ex(sctx, et, &len));

    // Format TCP buffer
    memcpy(buf, iv, cipher_block);
    memcpy(buf + cipher_block, et, key_block + hash_block);

    write(connfd2, (const unsigned char *)buf, cipher_block + key_block + hash_block);

    // Free pointers used by KEM
    free(buf);
    free(entropy);
    free(personal);
    free(server_pk);
    free(server_sk);
    free(ct);
    free(css1);
    free(client_pk);
    free(css2);
    free(rand1);
    free(rand2);
    free(peer_pk);
    free(pss1);
    free(pss2);

    // Free pointers used by AES and SHA-3
    free(iv);
    free(tag1);
    free(tag2);
    free(et);
    free(input);
    free(uid1);
    free(uid2);
    EVP_CIPHER_CTX_free(sctx);
    EVP_MD_CTX_free(hctx);

    free(session);

    close(connfd1); // Close the connection
    close(connfd2); // Close the connection
    close(sockfd); // Close the socket
    return 0;
}
