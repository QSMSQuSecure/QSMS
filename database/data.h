#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "../crypto/saber/Reference_Implementation_KEM/SABER_params.h"

#define SIZE 65536
#define BIOBYTES 128

typedef struct identity {
   u_int8_t ID[SABER_SEEDBYTES];
} ID_t;

typedef struct biometric {
   u_int8_t BIO[BIOBYTES];
} bio_t;

typedef struct publicKey {
   u_int8_t PUB[SABER_INDCPA_PUBLICKEYBYTES];
} pub_t;

typedef struct User {
   ID_t *id;
   bio_t *bio;
   pub_t *pub;
} user_t;

typedef struct Database {
   user_t *database[SIZE];
} data_t;

data_t *init(void);

u_int16_t size(data_t *data);

u_int16_t hashIndex(read_t *input);

u_int16_t find(data_t *data, read_t *input);

bool exists(data_t *data, read_t *input);

bool validate(data_t *data, write_t *input);

pub_t *getPublicKey(data_t *data, read_t *input);

void insert(data_t *data, write_t *input, pub_t pub);

void empty(data_t *data, read_t *input);

void freeData(data_t *data);

