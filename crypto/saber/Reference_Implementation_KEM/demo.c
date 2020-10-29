#include <string.h>

void test_kem_cpa(char *initMess, char *initSend, char *initRec);

// Demo
void test_kem_cpa(char *initMess, char *initSend, char *initRec) {
    uint8_t message[SABER_SEEDBYTES]; // Stored message of length SABER_SEEDBYTES
    uint8_t sendID[SABER_SEEDBYTES]; // Stored sender ID of length SABER_SEEDBYTES
    uint8_t recID[SABER_SEEDBYTES]; // Stored recipient ID of length SABER_SEEDBYTES
    uint8_t spk[SABER_INDCPA_PUBLICKEYBYTES]; // Sender public key of length SABER_INDCPA_PUBLICKEYBYTES
    uint8_t ssk[SABER_INDCPA_SECRETKEYBYTES]; // Sender secret key of length SABER_INDCPA_SECRETKEYBYTES
    uint8_t rpk[SABER_INDCPA_PUBLICKEYBYTES]; // Recipient public key of length SABER_INDCPA_PUBLICKEYBYTES
    uint8_t rsk[SABER_INDCPA_SECRETKEYBYTES]; // Recipient secret key of length SABER_INDCPA_SECRETKEYBYTES
    uint8_t ct[SABER_BYTES_CCA_DEC]; // Encrpted message of length SABER_BYTES_CCA_DEC
    uint8_t seed_sp[SABER_NOISE_SEEDBYTES]; // Noise seed of length SABER_NOISE_BYTES
    uint8_t m[SABER_SEEDBYTES]; // Decrypted message of length SABER_KEYBYTES
    uint16_t i; // Loop counter    
    
    // Limit each to SABER_SEEDBYTES
    for (i = 0; i < SABER_SEEDBYTES; i++) {
        // Copy one byte per iteration
	message[i] = initMess[i];
	sendID[i] = initSend[i];
	recID[i] = initRec[i];
    } 

    indcpa_kem_keypair(spk, ssk, sendID); // Generate sender public key and secret key from sender ID
    indcpa_kem_keypair(rpk, rsk, recID); // Generate recipient public key and secret key from recipient ID
    

    randombytes(seed_sp, SABER_NOISE_SEEDBYTES); // Generate random bytes for the noise seed
    indcpa_kem_enc(message, seed_sp, rpk, ct); // Encrypt message using recipient public key and store to ct
    
    indcpa_kem_dec(rsk, ct, m); // Decprypt message using recipient secret key and store to m

    printf("Sender ID: %s\n", sendID); // Print sender ID
    printf("Recipient ID: %s\n", recID); // Print recipient ID

    printf("Message: %s\n", message); // Print message

    printf("Recipient Public Key: ");
    for (i = 0; i < SABER_INDCPA_PUBLICKEYBYTES; i++) {
        printf("%02X", rpk[i]); // Print one byte of recipient public key
    }
    printf("\n");
    

    printf("Encrypted Message: ");
    for (i = 0; i < SABER_BYTES_CCA_DEC; i++) {
        printf("%02x", ct[i]); // Print one byte of encypted message
    }
    printf("\n");

    printf("Recipient Secret Key: ");
    for (i = 0; i < SABER_INDCPA_SECRETKEYBYTES; i++) {
        printf("%02x", rsk[i]); // Print one byte of recipient secret key
    }
    printf("\n");

    printf("Decrypted Message: %s\n", m); // Print decrypted message

    printf("Sender Public Key: ");
    for (i = 0; i < SABER_INDCPA_PUBLICKEYBYTES; i++) {
	printf("%02x", spk[i]); // Print one byte of sender public key
    }
    printf("\n");

    printf("Sender Secret Key: ");
    for (i = 0; i < SABER_INDCPA_SECRETKEYBYTES; i++) {
	printf("%02x", ssk[i]); // Print one byte of sender public key
    }
    
    printf("\n");

    if (memcmp(message, m, SABER_SEEDBYTES) == 0) printf("PASSED!\n");
    else printf("FAILED!\n");
}

