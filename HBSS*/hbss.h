#ifndef HBSS_H
#define HBSS_H

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

struct key_size_cell { 
    unsigned char key[(KEY_SIZE + CHAR_BIT - 1) / CHAR_BIT];
};

typedef struct {
    struct key_size_cell **Seeds;
    struct key_size_cell *Commitment; 
} HBSS_key_pair;


typedef struct  {
    unsigned char digest_cell[(DIGEST_LEN_K + CHAR_BIT - 1) / CHAR_BIT];

} HBSS_digest_message;

typedef struct  {
    unsigned char digest_cell[(KEY_SIZE + CHAR_BIT - 1) / CHAR_BIT]; 

} HBSS_digest_signature;

struct signature_size_cell { 
    unsigned char signature_cell[(KEY_SIZE + CHAR_BIT - 1) / CHAR_BIT]; 
};

typedef struct  {
    struct signature_size_cell signature[DIGEST_LEN_K];

} HBSS_signature;


void key_gen(HBSS_key_pair *key_pair) ;

void free_memory(HBSS_key_pair *key_pair);

void sign(unsigned char *message, HBSS_signature *signature, struct key_size_cell **Seeds);

int verify(unsigned char *message, HBSS_signature *signature, struct key_size_cell *Commitment) ;
#endif