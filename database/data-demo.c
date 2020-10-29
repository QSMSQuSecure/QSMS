#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include "../PQC_IBE/Reference_Implementation_KEM/SABER_params.h"

#define SIZE 200000
#define BIOBYTES 128

typedef struct DataItem {
   u_int8_t ID[SABER_SEEDBYTES];
   u_int8_t bio[BIOBYTES];
   u_int8_t pub[SABER_PUBLICKEYBYTES];
} dataItem;

dataItem *newItem(u_int8_t ID[SABER_SEEDBYTES], u_int8_t bio[BIOBYTES], u_int8_t pub[SABER_PUBLICKEYBYTES]) {
   dataItem *new;
   int i;

   new = (dataItem*) malloc(sizeof(dataItem));
   for (i = 0; i < SABER_SEEDBYTES; i++) new->ID[i] = ID[i];
   for (i = 0; i < BIOBYTES; i++) new->bio[i] = bio[i];
   for (i = 0; i < SABER_PUBLICKEYBYTES; i++) new->pub[i] = pub[i];
   return new;
}

int hashCode(u_int8_t ID[SABER_SEEDBYTES]) {
   return ((size_t)ID) % SIZE;
}

dataItem *search(dataItem *database[SIZE], u_int8_t ID[SABER_SEEDBYTES], u_int8_t bio[BIOBYTES]) {
   
   int i;
   int numEq;
	
   //get the hash 
   int hashIndex;
   hashIndex = hashCode(ID);
	
   //move in array until an empty 
   while(database[hashIndex] != NULL) {

      numEq = 0;
      if (database[hashIndex]->ID != NULL) {
         for (i = 0; i < SABER_SEEDBYTES; i++) {
            if (database[hashIndex]->ID[i] == ID[i]) numEq++;
         }
	 for (i = 0; i < BIOBYTES; i++) {
	    if (database[hashIndex]->bio[i] == bio[i]) numEq++;
	 }
      }
      if (numEq == SABER_SEEDBYTES + BIOBYTES) return database[hashIndex];
      
			
      //go to next cell
      ++hashIndex;
		
      //wrap around the table
      hashIndex %= SIZE;
   }
	
   return NULL;        
}

void insert(dataItem *database[SIZE], u_int8_t ID[SABER_SEEDBYTES], u_int8_t bio[BIOBYTES], u_int8_t pub[SABER_PUBLICKEYBYTES]) {

   int i;
   int hashIndex;
   dataItem *item;

   item = newItem(ID, bio, pub);

   //get the hash 
   hashIndex = hashCode(ID);

   //move in array until an empty cell
   while(database[hashIndex] != NULL) {
      //go to next cell
      hashIndex++;
		
      //wrap around the table
      hashIndex %= SIZE;
   }

   database[hashIndex] = item;
   return;
}

void delete(dataItem *database[SIZE], u_int8_t ID[SABER_SEEDBYTES], u_int8_t bio[BIOBYTES]) {

   int hashIndex;
   int numEq;
   int i;

   //get the hash 
   hashIndex = hashCode(ID);

   //move in array until an empty
   while(database[hashIndex] != NULL) {

      numEq = 0;
      if (database[hashIndex]->ID != NULL) {
         for (i = 0; i < SABER_SEEDBYTES; i++) {
            if (database[hashIndex]->ID[i] == ID[i]) numEq++;
         }
	 for (i = 0; i < BIOBYTES; i++) {
            if (database[hashIndex]->bio[i] == bio[i]) numEq++;
	 }
      }
      if (numEq == SABER_SEEDBYTES + BIOBYTES) {
         free((void*)(database[hashIndex]));
	 database[hashIndex] = NULL;
      }
      //go to next cell
      ++hashIndex;
		
      //wrap around the table
      hashIndex %= SIZE;
   }              
}

int main() {

   dataItem *database[SIZE];
   dataItem *item;
   u_int8_t ID[SABER_SEEDBYTES];
   u_int8_t bio[BIOBYTES];
   u_int8_t pub[SABER_PUBLICKEYBYTES];
   int i;

   
   for (i = 0; i < SIZE; i++) database[i] = NULL;

   for (i = 0; i < SABER_SEEDBYTES; i++) ID[i] = i;
   for (i = 0; i < BIOBYTES; i++) bio[i] = i;
   for (i = 0; i < SABER_PUBLICKEYBYTES; i++) pub[i] = i;

   insert(database, ID, bio, pub);

   item = search(database, ID, bio);

   if (item != NULL) {
      printf("Element found: ");
      for (i = 0; i < SABER_SEEDBYTES; i++) printf("%02x", item->ID[i]);
      printf("\n");
      printf("Biometric: ");
      for (i = 0; i < BIOBYTES; i++) printf("%02x", item->bio[i]);
      printf("\n");
      printf("Public Key: ");
      for (i = 0; i < SABER_PUBLICKEYBYTES; i++) printf("%02x", item->pub[i]);
      printf("\n\n");
   } else {
      printf("Error\n");
   }

   delete(database, ID, bio);

   item = search(database, ID, bio);

   if (item != NULL) {
      printf("Error\n");
   } else {
      printf("Element not found\n");
   }

   return 0;
}

