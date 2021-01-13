#ifndef randombytes_H
#define randombytes_H

#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

#define randombytes(buf, size) get_random_bytes(buf, size)


static inline ssize_t get_random_bytes(uint8_t *out, size_t len)
{
	ssize_t ret;
	int fd;

#if defined(__OpenBSD__) || (defined(__APPLE__) && MAC_OS_X_VERSION_MIN_REQUIRED >= MAC_OS_X_VERSION_10_12) || (defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25)))
	ret = getentropy(out, len);
	if (!ret)
		return len;
#endif

#if defined(__NR_getrandom) && defined(__linux__)
	ret = syscall(__NR_getrandom, out, len, 0);
	if (ret >= 0)
		return ret;
#endif

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
		return fd;
	ret = read(fd, out, len);
	close(fd);
	return ret;
}

#ifdef __cplusplus
}
#endif

#endif
