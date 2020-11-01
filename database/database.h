#include "data.h"

#define BUFFERSIZE (1 + SABER_SEEDBYTES + BIOBYTES + 1)
#define READSIZE (1 + SABER_SEEDBYTES + 1)
#define WRITESIZE BUFFERSIZE

typdef struct Buffer {

   u_int8_t input[BUFFERSIZE];

} buffer_t;

typedef struct Read {

   u_int8_t read[READSIZE];

} read_t;

typedef struct Write {

   u_int8_t write[WRITESIZE];

} write_t;

void dostuff(int sock);

void error(char *msg);

pub_t readBuf(buffer_t buffer);

pub_t *userRead(read_t input);

pub_t *userWrite(write_t input);
