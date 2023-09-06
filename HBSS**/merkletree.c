#include "merkletree.h"

MerkleTreeNode *create_leaf(struct key_size_cell *hash) {
    MerkleTreeNode *node = malloc(sizeof(MerkleTreeNode));
    node->hash = *hash;
    node->left = NULL;
    node->right = NULL;
    return node;
}

MerkleTreeNode *create_parent(MerkleTreeNode *left, MerkleTreeNode *right) {
    MerkleTreeNode *node = malloc(sizeof(MerkleTreeNode));
    node->left = left;
    node->right = right;

    // The hash of the parent node is the hash of the concatenation of the children hashes
    unsigned char children_hashes[2 * KEY_SIZE_BYTES];
    memcpy(children_hashes, left->hash.key, KEY_SIZE_BYTES);
    memcpy(children_hashes + KEY_SIZE_BYTES, right->hash.key, KEY_SIZE_BYTES);

    if (KEY_SIZE_BYTES == 32) {
        SHA256(children_hashes, 2 * KEY_SIZE_BYTES, node->hash.key);
    } else if (KEY_SIZE_BYTES == 64) {
        SHA512(children_hashes, 2 * KEY_SIZE_BYTES, node->hash.key);
    }

    return node;
}

MerkleTreeNode *create_tree(struct key_size_cell *hashes, int num_hashes) {
    MerkleTreeNode **nodes = malloc(num_hashes * sizeof(MerkleTreeNode*));
    for (int i = 0; i < num_hashes; i++) {
        nodes[i] = create_leaf(&hashes[i]);
    }

    int num_nodes = num_hashes;
    while (num_nodes > 1) {
        if (num_nodes % 2 != 0) {
            nodes[num_nodes++] = nodes[num_nodes - 1];  // Duplicate last node if number of nodes is odd
        }
        for (int i = 0; i < num_nodes / 2; i++) {
            nodes[i] = create_parent(nodes[2 * i], nodes[2 * i + 1]);
        }
        num_nodes /= 2;
    }

    MerkleTreeNode *root = nodes[0];
    free(nodes);
    return root;
}

void get_root(MerkleTreeNode *root, struct key_size_cell *root_hash) {
    *root_hash = root->hash;
}


void get_proof(MerkleTreeNode *root, int leaf_index, struct key_size_cell *proof, int *proof_length) {
    *proof_length = 0;

    MerkleTreeNode *node = root;
    int num_leaves = 1;
    while (node->left != NULL) {
        num_leaves *= 2;
        if (leaf_index < num_leaves / 2) {
            proof[(*proof_length)++] = node->right->hash;
            node = node->left;
        } else {
            proof[(*proof_length)++] = node->left->hash;
            node = node->right;
            leaf_index -= num_leaves / 2;
        }
    }
}

void free_merkle_tree(MerkleTreeNode *root) {
    if (root == NULL) {
        return;
    }

    free_merkle_tree(root->left);
    free_merkle_tree(root->right);

    free(root);
}