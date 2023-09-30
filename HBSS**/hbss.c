#include "hbss.h"

void key_gen(HBSS_key_pair *key_pair) {

    key_pair->secret_key = malloc(2 * M * sizeof(struct key_size_cell));
    for (size_t i = 0; i < 2*M; i++) {
        RAND_bytes(key_pair->secret_key[i].key, KEY_SIZE_BYTES);
    }    
    key_pair->tree = create_tree(key_pair->secret_key , 2 * M);

}

MerkleTreeNode *create_leaf(struct key_size_cell *secret_key) {
    MerkleTreeNode *node = malloc(sizeof(MerkleTreeNode));
    struct key_size_cell *hash = malloc(sizeof(struct key_size_cell));
    SHA256(secret_key->key, KEY_SIZE_BYTES, hash->key);
    node->hash = *hash;
    node->left = NULL;
    node->right = NULL;
    return node;
}

MerkleTreeNode *create_parent(MerkleTreeNode *left, MerkleTreeNode *right) {
    MerkleTreeNode *node = malloc(sizeof(MerkleTreeNode));
    node->left = left;
    node->right = right;

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

MerkleTreeNode *create_tree(struct key_size_cell *secret_keys, int num_hashes) {
    MerkleTreeNode **nodes = malloc(num_hashes * sizeof(MerkleTreeNode*));
    for (int i = 0; i < num_hashes; i++) {
        
        nodes[i] = create_leaf(&secret_keys[i]);

    }

    int num_nodes = num_hashes;
    while (num_nodes > 1) {
        if (num_nodes % 2 != 0) {
            nodes[num_nodes++] = nodes[num_nodes - 1];  
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

void free_memory(HBSS_key_pair *key_pair) {
    free_merkle_tree(key_pair->tree);
    free(key_pair->secret_key);
}
void sign(unsigned char *message, HBSS_signature *signature, struct key_size_cell *secret_key, MerkleTreeNode *root) { 
    
    unsigned char buffer[strlen((char*) message)+ ((int)ceil(log10(DIGEST_LEN_K))+1)]; 
    HBSS_digest_message D;
    HBSS_digest_message D_j;
    SHA512(message, strlen((char*) message), D.digest_cell); 

    for(size_t j=0;j<DIGEST_LEN_K;j++){ 


        sprintf(buffer, "%s%d", message, j); 
        SHA512(buffer, strlen(buffer), D_j.digest_cell); 

        union { 
            unsigned char c[8];
            unsigned long i_j;
        } mod;

        mod.i_j = 0; 

        size_t sz = sizeof D_j.digest_cell / sizeof D_j.digest_cell[0]; 
        size_t n = 0; 

        for( size_t i = sz; i && n < sizeof mod; ) {
            mod.c[ n++ ] = D_j.digest_cell[ --i ]; 
        }

        int N = LEN_M;
        mod.i_j &= (1<<N)-1; 



        int bit = (D.digest_cell[j/8] >> (7-(j%8))) & 1;


        int path_length;
        struct key_size_cell path[LOG_2_2M ];
        get_path(root, 2*mod.i_j+bit, path, &path_length);

        memcpy(signature->signature[j].signature_cell, secret_key[2*mod.i_j+bit].key, KEY_SIZE_BYTES);
        for(size_t i=1; i<LOG_2_2M +1; i++){    
            memcpy(signature->signature[j].signature_cell + (i)*KEY_SIZE_BYTES, path[LOG_2_2M-i].key, KEY_SIZE_BYTES);
        }

    }   
    return 1;
    
}

void get_path(MerkleTreeNode *root, int leaf_index, struct key_size_cell *path, int *path_length) {
    int i = 0,k = 0;

    int level = LOG_2_2M;

    *path_length = 0; 
    int half_number_leafs = M;

    MerkleTreeNode *current_node = root;
    while (level >0) {        

        if( leaf_index < (half_number_leafs / pow(2, i)) ) {
            memcpy(path[*path_length].key, current_node->right->hash.key, KEY_SIZE_BYTES);
            (*path_length)++;            
            current_node = current_node->left;
            
        } else {
            memcpy(path[*path_length].key, current_node->left->hash.key, KEY_SIZE_BYTES);
            (*path_length)++;
            current_node = current_node->right;
            leaf_index -= (half_number_leafs / pow(2, i));
        }
        i++;
        level--;

    }
}

int verify(unsigned char *message, HBSS_signature *signature, struct key_size_cell public_key ) {

    int j;  
    int i_j; 
    unsigned char buffer[strlen((char*) message)+((int)ceil(log10(DIGEST_LEN_K))+1)];
    HBSS_digest_message D;
    HBSS_digest_message D_j;
    HBSS_digest_signature D_sign_j;
    
    SHA512(message, strlen((char*) message), D.digest_cell); 
    for(j=0;j<DIGEST_LEN_K;j++){ 
        sprintf(buffer, "%s%d", message, j);
        SHA512(buffer, strlen(buffer), D_j.digest_cell); 

        union { 
            unsigned char c[8];
            unsigned long i_j;
        } mod;

        mod.i_j = 0; 

        size_t sz = sizeof D_j.digest_cell / sizeof D_j.digest_cell[0]; 
        size_t n = 0; 

        for( size_t i = sz; i && n < sizeof mod; ) {
            mod.c[ n++ ] = D_j.digest_cell[ --i ]; 
        }

        int N = LEN_M;
        mod.i_j &= (1<<N)-1; 

        int bit = (D.digest_cell[j/8] >> (7-(j%8))) & 1;        

        int preimage_number = 2*mod.i_j+bit;

        struct key_size_cell sha_to_the_root;
        struct key_size_cell tmp;

        struct key_size_cell concat[2];

        memcpy(sha_to_the_root.key, signature->signature[j].signature_cell, KEY_SIZE_BYTES);

        SHA256(sha_to_the_root.key, KEY_SIZE_BYTES, sha_to_the_root.key);


        for (size_t i = 1; i < LOG_2_2M +1; i++) {

            memcpy(tmp.key, signature->signature[j].signature_cell + (i)*KEY_SIZE_BYTES, KEY_SIZE_BYTES);
            int last_bit = preimage_number & 1;

            if (last_bit == 0) {
                memcpy(concat[0].key, sha_to_the_root.key, KEY_SIZE_BYTES);
                memcpy(concat[1].key, tmp.key, KEY_SIZE_BYTES);
                SHA256(concat, 2*KEY_SIZE_BYTES, sha_to_the_root.key);

            } else {
                memcpy(concat[0].key, tmp.key, KEY_SIZE_BYTES);
                memcpy(concat[1].key, sha_to_the_root.key, KEY_SIZE_BYTES);
                SHA256(concat, 2*KEY_SIZE_BYTES, sha_to_the_root.key);
            }

            preimage_number = preimage_number >> 1;
        }

        if (memcmp(sha_to_the_root.key, public_key.key, KEY_SIZE_BYTES) != 0) {
            printf("error in root\n");
            return 0;
        }
    }    
    return 1;
}


void xor(unsigned char* a, unsigned char* b, unsigned char* out, int len) {
    for (int i = 0; i < len; i++) {
        out[i] = a[i] ^ b[i];
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

void print_tree(MerkleTreeNode* node, int depth) {
    if (node == NULL)
        return;

    print_tree(node->right, depth + 1);

    for(int i = 0; i < depth; i++)
        printf("\t"); 

    for(int i = 0; i < KEY_SIZE_BYTES; i++)
        printf("%02X", node->hash.key[i]);
    printf("\n");

    print_tree(node->left, depth + 1);
}