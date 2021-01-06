#include <stdlib.h>
#include <stdio.h>

#include "../crypto/saber/Reference_Implementation_KEM/api.h"
#include "../crypto/saber/Reference_Implementation_KEM/rng.c"
#include "../crypto/saber/Reference_Implementation_KEM/pack_unpack.c"
#include "../crypto/saber/Reference_Implementation_KEM/poly.c"
#include "../crypto/saber/Reference_Implementation_KEM/fips202.c"
#include "../crypto/saber/Reference_Implementation_KEM/verify.c"
#include "../crypto/saber/Reference_Implementation_KEM/cbd.c"
#include "../crypto/saber/Reference_Implementation_KEM/SABER_indcpa.c"
#include "../crypto/saber/Reference_Implementation_KEM/kem.c"

int main () {

    unsigned char *pk;
    unsigned char *sk;
    unsigned char *ct;
    unsigned char *ss1;
    unsigned char *ss2;
    u_int16_t i;

    pk = calloc(CRYPTO_PUBLICKEYBYTES, 1);
    sk = calloc(CRYPTO_SECRETKEYBYTES, 1);
    ct = calloc(CRYPTO_CIPHERTEXTBYTES, 1);
    ss1 = calloc(CRYPTO_BYTES, 1);
    ss2 = calloc(CRYPTO_BYTES, 1);

    //randombytes_init(entropy_input, personalized_string, security_strength);
    crypto_kem_keypair(pk, sk);

    for (i = 0; i < CRYPTO_PUBLICKEYBYTES; i++) printf("%02x", pk[i]); printf("\n");
    for (i = 0; i < CRYPTO_SECRETKEYBYTES; i++) printf("%02x", sk[i]); printf("\n");
    printf("\n");

    crypto_kem_enc(ct, ss1, pk);
    crypto_kem_dec(ss2, ct, sk);
    for (i = 0; i < CRYPTO_CIPHERTEXTBYTES; i++) printf("%02x", ct[i]); printf("\n");
    for (i = 0; i < CRYPTO_BYTES; i++) printf("%02x", ss1[i]); printf("\n");
    for (i = 0; i < CRYPTO_BYTES; i++) printf("%02x", ss2[i]); printf("\n");
    printf("\n");

    crypto_kem_enc(ct, ss1, pk);
    crypto_kem_dec(ss2, ct, sk);
    for (i = 0; i < CRYPTO_CIPHERTEXTBYTES; i++) printf("%02x", ct[i]); printf("\n");
    for (i = 0; i < CRYPTO_BYTES; i++) printf("%02x", ss1[i]); printf("\n");
    for (i = 0; i < CRYPTO_BYTES; i++) printf("%02x", ss2[i]); printf("\n");
    printf("\n");

    crypto_kem_enc(ct, ss1, pk);
    crypto_kem_dec(ss2, ct, sk);
    for (i = 0; i < CRYPTO_CIPHERTEXTBYTES; i++) printf("%02x", ct[i]); printf("\n");
    for (i = 0; i < CRYPTO_BYTES; i++) printf("%02x", ss1[i]); printf("\n");
    for (i = 0; i < CRYPTO_BYTES; i++) printf("%02x", ss2[i]); printf("\n");
    printf("\n");
    
    free(pk);
    free(sk);
    free(ct);
    free(ss1);
    free(ss2);

    return 0;
}
