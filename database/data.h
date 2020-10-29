#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "../PQC_IBE/Reference_Implementation_KEM/SABER_params.h"

#define SIZE 200000
#define BIOBYTES 128

typedef struct identity {
   u_int8_t ID[SABER_SEEDBYTES];
} id_t;

typedef struct biometric {
   u_int8_t BIO[BIOBYTES];
} bio_t;

typedef struct publicKey {
   u_int8_t PUB[SABER_PUBLICKEYBYTES];
} pub_t;

typedef struct User {
   id_t *id;
   bio_t *bio;
   pub_t *pub;
} user_t;

typedef struct Database {
   user_t database[SIZE];
} data_t;

user_t init(id_t id, bio_t bio, pub_t pub);

int hash(id_t id);

int exists(id_t id);

bool validate(id_t id, bio_t bio);

pub_t getPublicKey(id_t id);

void insert(data_t data, id_t id, bio_t bio, pub_t pub);

void remove(data_t data, id_t id, bio_t bio);

void error(char *msg);

void newProcess(int sock);

