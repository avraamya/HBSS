#ifndef STATELESS_LAMPORT_H
#define STATELESS_LAMPORT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <limits.h>
#include <math.h>


#include "param.h"

struct key_size_cell { //big assumption that the char is 8 bits and not 16 bits
    unsigned char key[(KEY_SIZE + CHAR_BIT - 1) / CHAR_BIT]; //64 bytes
};

typedef struct  {
    struct key_size_cell **secret_key;
    struct key_size_cell **public_key;

} stateless_lamport_key_pair;

typedef struct  {
    //digest is in total 512 bits
    unsigned char digest_cell[(DIGEST_LEN_K + CHAR_BIT - 1) / CHAR_BIT]; //64 bytes

} stateless_lamport_digest_message;

typedef struct  {
    //digest is in total 512 bits
    unsigned char digest_cell[(KEY_SIZE + CHAR_BIT - 1) / CHAR_BIT]; //32 bytes

} stateless_lamport_digest_signature;

struct signature_size_cell { 
    //same idea as the digest
    unsigned char signature_cell[(KEY_SIZE + CHAR_BIT - 1) / CHAR_BIT]; //32 bytes

};

typedef struct  {
    //digest is in total 512 bits
    struct signature_size_cell signature[DIGEST_LEN_K];

} stateless_lamport_signature;


void key_gen(stateless_lamport_key_pair *key_pair) ;

void free_memory(stateless_lamport_key_pair *key_pair);

//void sign(unsigned char *message, stateless_lamport_signature *signature, stateless_lamport_key_pair *key_pair) ;
void sign(unsigned char *message, stateless_lamport_signature *signature, struct key_size_cell **secret_key) ;

//int verify(unsigned char *message, stateless_lamport_signature *signature, stateless_lamport_key_pair *key_pair ) ;
int verify(unsigned char *message, stateless_lamport_signature *signature, struct key_size_cell **public_key) ;
#endif