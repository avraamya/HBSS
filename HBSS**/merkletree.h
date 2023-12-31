#ifndef MERKLETREE_H
#define MERKLETREE_H

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

typedef struct MerkleTreeNode MerkleTreeNode;

struct MerkleTreeNode {
    struct key_size_cell hash;
    MerkleTreeNode *left;
    MerkleTreeNode *right;
};

MerkleTreeNode *create_leaf(struct key_size_cell *hash);
MerkleTreeNode *create_parent(MerkleTreeNode *left, MerkleTreeNode *right);
MerkleTreeNode *create_tree(struct key_size_cell *hashes, int num_hashes);
void get_root(MerkleTreeNode *root, struct key_size_cell *root_hash);
void get_proof(MerkleTreeNode *root, int leaf_index, struct key_size_cell *proof, int *proof_length);
void free_merkle_tree(MerkleTreeNode *root);

#endif
