#include "operations.h"

#include "crypto_stream_aes256ctr.h"
#include "controlbits.h"
#include "randombytes.h"
#include "params.h"
#include "sk_gen.h"
#include "pk_gen.h"
#include "util.h"

#include <stdint.h>
#include <string.h>

int crypto_kem_mceliece460896_avx_keypair
(
       unsigned char *pk,
       unsigned char *sk 
)
{
	int i;
	unsigned char seed[ 32 ];
	unsigned char r[ SYS_T*2 + (1 << GFBITS)*sizeof(uint32_t) + SYS_N/8 + 32 ];
	unsigned char nonce[ 16 ] = {0};
	unsigned char *rp;

	gf f[ SYS_T ]; // element in GF(2^mt)
	gf irr[ SYS_T ]; // Goppa polynomial
	uint32_t perm[ 1 << GFBITS ]; // random permutation 

	randombytes(seed, sizeof(seed));

	while (1)
	{
		rp = r;
		crypto_stream_aes256ctr(r, sizeof(r), nonce, seed);
		memcpy(seed, &r[ sizeof(r)-32 ], 32);

		for (i = 0; i < SYS_T; i++) {
                    f[i] = load2(rp + i*2);
                }
                rp += sizeof(f);

		if (genpoly_gen(irr, f)) continue;

		for (i = 0; i < (1 << GFBITS); i++) {
                    perm[i] = load4(rp + i*4);
                }
                rp += sizeof(perm);

		if (perm_check(perm)) continue;

		for (i = 0; i < SYS_T;   i++) {
                    store2(sk + SYS_N/8 + i*2, irr[i]);
                }
		if (pk_gen(pk, sk + SYS_N/8, perm)) continue;

		memcpy(sk, rp, SYS_N/8);
		controlbits(sk + SYS_N/8 + IRR_BYTES, perm);

		break;
	}

	return 0;
}

