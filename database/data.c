#include "data.h"
#include "database.h"

data_t *init(void) {
   
   return (data_t*) malloc(sizeof(data_t));
}

u_int16_t size(data_t *data) {

   u_int32_t i;
   u_int16_t filled;

   i = 0;
   filled = 0;

   while (i < SIZE) {
	   
      if (data->database[i] != NULL) filled++;
      i++;
   }

   return filled;
}

u_int16_t hashIndex(read_t *input) {

   u_int16_t i;
   u_int16_t index;

   index = 0;
   for (i = 0; i < SABER_SEEDBYTES; i++) index += input->id->ID[i];
   
   return index;
}

bool exists(data_t *data, read_t input) {
   
   bool found;
   u_int32_t i;
   u_int16_t j;
   u_int16_t numEq;

   found = false;
   i = hashIndex(input);
   
   while (!found && i < SIZE) {

      numEq = 0;
     
      if (data->database[i] != NULL) {
     
         for (j = 0; j < SABER_SEEDBYTES; j++) {

            if (data->database[i]->id->ID[j] == input->id->ID[j]) numEq++;
         }
      }

      if (numEq == SABER_SEEDBYTES) found = true;
      i++;
   }

   return found;
}

u_int16_t find(data_t *data, read_t *input) {
   
   u_int16_t i;
   u_int16_t numEq; 
   u_int16_t j;
   bool found;
      
   i = hashIndex(input);
   found = false;

   while (!found) {

      numEq = 0;
      if (data->database[i] != NULL) {

         for (j = 0; j < SABER_SEEDBYTES; j++) {
     
            if (data->database[i]->id->ID[j] == input->id->ID[j]) numEq++;
         }
      }
   
      if (numEq == SABER_SEEDBYTES) found = true;
      if (!found) i++;
   }

   free(input->id);
   free(input);

   return i;
}

bool validate(data_t *data, write_t *input) {

   u_int16_t i;
   u_int16_t numEq;
   u_int16_t j;

   i = find(data, input);
   numEq = 0;
   
   for (j = 0; j < BIOBYTES; j++) {

      if (data->database[i]->bio->BIO[j] == input->bio->BIO[j]) numEq++;
   }

   if (numEq == BIOBYTES) return true;
   return false;
}

pub_t *getPublicKey(data_t *data, read_t *input) {

   u_int16_t i;

   i = find(data, input);
   return data->database[i]->pub;
}

void insert(data_t *data, write_t input, pub_t pub) {

   u_int16_t i;
   u_int16_t j;
   read_t *temp;

   tmp = (read_t*) malloc(sizeof(read_t));
   tmp->id = (ID_t*) malloc(sizeof(ID_t));

   for (j = 0; j < READSIZE; j++) tmp->id[j] = input->id[j];
   i = hashIndex(tmp);

   free(tmp->id);
   free(tmp);

   while (data->database[i] != NULL) i++;

   data->database[i] = (user_t*) malloc(sizeof(user_t));
   data->database[i]->id = (ID_t*) malloc(sizeof(ID_t));
   data->database[i]->bio = (bio_t*) malloc(sizeof(bio_t));
   data->database[i]->pub = (pub_t*) malloc(sizeof(pub_t));

   for (j = 0; j < SABER_SEEDBYTES; j++) data->database[i]->id->ID[j] = input->id->ID[j];
   for (j = 0; j < BIOBYTES; j++) data->database[i]->bio->BIO[j] = input->bio->BIO[j];
   for (j = 0; j < SABER_PUBLICKEYBYTES; j++) data->database[i]->pub->PUB[j] = pub.PUB[j];
}

void empty(data_t *data, read_t input) {

   u_int16_t i;

   i = find(data, input);
   free(data->database[i]->id);
   data->database[i]->id = NULL;
   free(data->database[i]->bio);
   data->database[i]->bio = NULL;
   free(data->database[i]->pub);
   data->database[i]->pub = NULL;
   free(data->database[i]);
   data->database[i] = NULL;
}

void freeData(data_t *data) {
   
   free(data);
}

