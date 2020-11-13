// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <errno.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#ifdef __linux__
#include <sys/syscall.h>
#endif
#ifdef __APPLE__
#include <AvailabilityMacros.h>
#ifndef MAC_OS_X_VERSION_10_12
#define MAC_OS_X_VERSION_10_12 101200
#endif
#if MAC_OS_X_VERSION_MIN_REQUIRED >= MAC_OS_X_VERSION_10_12
#include <sys/random.h>
#endif
#endif

#include "curve25519.h"
#include "encoding.h"
#include "subcommands.h"

#include "mceliece/crypto_kem_mceliece.h"
#include "mceliece/randombytes.h"

/*
#ifndef WINCOMPAT
static inline bool __attribute__((__warn_unused_result__)) get_random_bytes(uint8_t *out, size_t len)
{
	ssize_t ret = 0;
	size_t i;
	int fd;

	if (len > 256) {
		errno = EOVERFLOW;
		return false;
	}

#if defined(__OpenBSD__) || (defined(__APPLE__) && MAC_OS_X_VERSION_MIN_REQUIRED >= MAC_OS_X_VERSION_10_12) || (defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25)))
	if (!getentropy(out, len))
		return true;
#endif

#if defined(__NR_getrandom) && defined(__linux__)
	if (syscall(__NR_getrandom, out, len, 0) == (ssize_t)len)
		return true;
#endif

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
		return false;
	for (errno = 0, i = 0; i < len; i += ret, ret = 0) {
		ret = read(fd, out + i, len - i);
		if (ret <= 0) {
			ret = errno ? -errno : -EIO;
			break;
		}
	}
	close(fd);
	errno = -ret;
	return i == len;
}

#else
#include "wincompat/getrandom.c"
#endif
*/

int genkey_main(int argc, char *argv[])
{
	uint8_t key[WG_KEY_LEN];
	char base64[WG_KEY_LEN_BASE64];
	struct stat stat;

	if (argc != 1) {
		fprintf(stderr, "Usage: %s %s\n", PROG_NAME, argv[0]);
		return 1;
	}

	if (!fstat(STDOUT_FILENO, &stat) && S_ISREG(stat.st_mode) && stat.st_mode & S_IRWXO)
		fputs("Warning: writing to world accessible file.\nConsider setting the umask to 077 and trying again.\n", stderr);

	if (!get_random_bytes(key, WG_KEY_LEN)) {
		perror("getrandom");
		return 1;
	}
	if (!strcmp(argv[0], "genkey"))
		curve25519_clamp_secret(key);

	key_to_base64(base64, key);
	puts(base64);
	return 0;
}

static inline FILE* sfopen(const char* fname, const char* mode)
{
        FILE *fp = fopen(fname, mode);
        if (!fp) {
                fprintf(stderr, "Failed to open file %s in mode %s\n", fname, mode);
                exit(1);
        }
        return fp;
}

// generate a McEliece key pair
int genkey_mc_main(int argc, char *argv[])
{
        if (argc != 3) {
                fprintf(stderr, "Usage: %s %s private_key_file public_key_file\n", PROG_NAME, argv[0]);
                return 1;
        }

        // TODO: check output file permission
        const size_t pk_size = sizeof(uint8_t) * crypto_kem_mceliece_PUBLICKEYBYTES;
        const size_t sk_size = sizeof(uint8_t) * crypto_kem_mceliece_SECRETKEYBYTES;

        uint8_t * const pk = malloc(pk_size);
        if (!pk) {
                fprintf(stderr, "Failed to allocate buffer of McEliece public key\n");
                return 1;
        }

        uint8_t * const sk = malloc(sk_size);
        if (!sk) {
                fprintf(stderr, "Failed to allocate buffer of McEliece private key\n");
                free(pk);
                return 1;
        }

        int ret_val;
        if ( (ret_val = crypto_kem_mceliece_keypair(pk, sk)) != 0) {
            fprintf(stderr, "Failed to generate the key pair: <%d>\n", ret_val);
            free(pk);
            free(sk);
            return 1;
        }

        // output pk and sk
        FILE *fp = sfopen(argv[1], "w");
        fwrite(sk, sk_size, 1, fp);
        fclose(fp);
        free(sk);

        fp = sfopen(argv[2], "w");
        fwrite(pk, pk_size, 1, fp);
        fclose(fp);
        free(pk);

        return 0;
}
