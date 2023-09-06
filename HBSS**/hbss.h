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

typedef struct MerkleTreeNode MerkleTreeNode;

struct MerkleTreeNode {
    struct key_size_cell hash;
    MerkleTreeNode *left;
    MerkleTreeNode *right;
};


typedef struct {
    struct key_size_cell Seeds[2];
    MerkleTreeNode *root;
} HBSS_key_pair;


typedef struct  {
    unsigned char digest_cell[(DIGEST_LEN_K + CHAR_BIT - 1) / CHAR_BIT];

} HBSS_digest_message;

typedef struct  {
    unsigned char digest_cell[(KEY_SIZE + CHAR_BIT - 1) / CHAR_BIT]; 

} HBSS_digest_signature;

struct signature_size_cell { 
    unsigned char signature_cell[((KEY_SIZE + CHAR_BIT - 1) * (LOG_2_2M+1) ) / CHAR_BIT]; 
};

typedef struct  {
    struct signature_size_cell signature[DIGEST_LEN_K];

} HBSS_signature;

void key_gen(HBSS_key_pair *key_pair) ;

void free_memory(HBSS_key_pair *key_pair);

//void sign(unsigned char *message, HBSS_signature *signature, struct key_size_cell (*Seeds)[2], MerkleTreeNode *root); 
void sign(unsigned char *message, HBSS_signature *signature, struct key_size_cell Seeds[2], MerkleTreeNode *root); 

int verify(unsigned char *message, HBSS_signature *signature, MerkleTreeNode *root );

MerkleTreeNode *create_leaf(struct key_size_cell *hash);
MerkleTreeNode *create_parent(MerkleTreeNode *left, MerkleTreeNode *right);
MerkleTreeNode *create_tree(struct key_size_cell *hashes, int num_hashes);
void get_root(MerkleTreeNode *root, struct key_size_cell *root_hash);
void get_proof(MerkleTreeNode *root, int leaf_index, struct key_size_cell *proof, int *proof_length);
void free_merkle_tree(MerkleTreeNode *root);
void get_path(MerkleTreeNode *root, int leaf_index, struct key_size_cell *path, int *path_length);


#endif