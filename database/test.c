#include "data.c"
#include "../crypto/saber/Reference_Implementation_KEM/SABER_params.h"

int main() {

   data_t *data;
   ID_t id;
   bio_t bio;
   pub_t pub;
   u_int32_t i;
   u_int16_t j;

   data = init();

   for (i = 0; i < SIZE; i++) data->database[i] = NULL;

   for (i = 0; i < SIZE; i++) {

      id.ID[0] = (u_int8_t)i;
      bio.BIO[0] = (u_int8_t)i;
      pub.PUB[0] = (u_int8_t)i;
      id.ID[1] = (u_int8_t) (i >> 8);
      bio.BIO[1] = (u_int8_t) (i >> 8);
      pub.PUB[1] = (u_int8_t) (i >> 8);
	   
      for (j = 2; j < SABER_SEEDBYTES; j++) id.ID[j] = 0x00;
      for (j = 2; j < BIOBYTES; j++) bio.BIO[j] = 0x00;
      for (j = 2; j < SABER_PUBLICKEYBYTES; j++) pub.PUB[j] = 0x00;

      insert(data, id, bio, pub);
   }

   for (i = 0; i < SIZE; i++) {

      id.ID[0] = (u_int8_t)i;
      bio.BIO[0] = (u_int8_t)i;
      pub.PUB[0] = (u_int8_t)i;
      id.ID[1] = (u_int8_t) (i >> 8);
      bio.BIO[1] = (u_int8_t) (i >> 8);
      pub.PUB[1] = (u_int8_t) (i >> 8);

      for (j = 2; j < SABER_SEEDBYTES; j++) id.ID[j] = 0x00;
      for (j = 2; j < BIOBYTES; j++) bio.BIO[j] = 0x00;
      for (j = 2; j < SABER_PUBLICKEYBYTES; j++) pub.PUB[j] = 0x00;

      empty(data, id);
   }

   freeData(data);

   return 0;
}
