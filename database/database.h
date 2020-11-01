#include "data.h"

#define BUFFERSIZE (1 + SABER_SEEDBYTES + BIOBYTES + 1)
#define READSIZE SABER_SEEDBYTES
#define WRITESIZE (BUFFERSIZE - 2)

typdef struct Buffer {

   u_int8_t input[BUFFERSIZE];

} buffer_t;

typedef struct Read {

   ID_t *id;

} read_t;

typedef struct Write {

   ID_t *id;
   bio_t *bio;

} write_t;

pub_t *readBuf(data_t *data, buffer_t buffer);

pub_t *userRead(data_t *data, read_t *input);

pub_t *userWrite(data_t *data, write_t *input);

void dostuff(int sock);

void error(char *msg);
