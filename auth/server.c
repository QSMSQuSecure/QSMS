#include <stdlib.h>
#include <stdio.h>

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

int main () {

    unsigned char *pk;
    unsigned char *sk;
    unsigned char *ct;
    unsigned char *ss;
    u_int16_t i;

    pk = calloc(CRYPTO_PUBLICKEYBYTES, 1);
    sk = calloc(CRYPTO_SECRETKEYBYTES, 1);
    ct = calloc(CRYPTO_CIPHERTEXTBYTES, 1);
    ss = calloc(CRYPTO_BYTES, 1);

    crypto_kem_keypair(pk, sk);

    for (i = 0; i < CRYPTO_PUBLICKEYBYTES; i++) printf("%02x", pk[i]); printf("\n");
    for (i = 0; i < CRYPTO_SECRETKEYBYTES; i++) printf("%02x", sk[i]); printf("\n");
    printf("\n");

    crypto_kem_enc(ct, ss, pk);
    crypto_kem_dec(ss, ct, sk);
    for (i = 0; i < CRYPTO_CIPHERTEXTBYTES; i++) printf("%02x", ct[i]); printf("\n");
    for (i = 0; i < CRYPTO_BYTES; i++) printf("%02x", ss[i]); printf("\n");
    printf("\n");

    crypto_kem_enc(ct, ss, pk);
    crypto_kem_dec(ss, ct, sk);
    for (i = 0; i < CRYPTO_CIPHERTEXTBYTES; i++) printf("%02x", ct[i]); printf("\n");
    for (i = 0; i < CRYPTO_BYTES; i++) printf("%02x", ss[i]); printf("\n");
    printf("\n");

    crypto_kem_enc(ct, ss, pk);
    crypto_kem_dec(ss, ct, sk);
    for (i = 0; i < CRYPTO_CIPHERTEXTBYTES; i++) printf("%02x", ct[i]); printf("\n");
    for (i = 0; i < CRYPTO_BYTES; i++) printf("%02x", ss[i]); printf("\n");
    printf("\n");
    free(pk);
    free(sk);
    free(ct);
    free(ss);

    return 0;
}
