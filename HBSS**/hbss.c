#include "hbss.h"

void key_gen(HBSS_key_pair *key_pair) {

    RAND_bytes(key_pair->Seeds[0].key, KEY_SIZE_BYTES); // random key
    RAND_bytes(key_pair->Seeds[1].key, KEY_SIZE_BYTES); // random key

    int i, j;

    struct key_size_cell r_j , t_2m_j;
    struct key_size_cell preimage;

    struct key_size_cell commitments[2 * M]; // Temporary array for storing commitments

    for (i = 0; i < 2 * M; i++) {
        memcpy(r_j.key, key_pair->Seeds[0].key, KEY_SIZE_BYTES); // r_j = s_0
        memcpy(t_2m_j.key, key_pair->Seeds[1].key, KEY_SIZE_BYTES); // t_2m_j = s_1

//        printf("r_j: ");
//        for (j = 0; j < KEY_SIZE_BYTES; j++) {
//            printf("%02x", r_j.key[j]);
//        }

        // r_j = H^i(s_0)
        //printf("i: %d\n", i);
        //printf("2m-i: %d\n", 2 * M - i);
        for (j = 0; j < i; j++){  
        //for (j = 0; j < 11; j++){
            if (KEY_SIZE_BYTES == 32) {
                SHA256(r_j.key, KEY_SIZE_BYTES, r_j.key);
            } else if (KEY_SIZE_BYTES == 64) {
                SHA512(r_j.key, KEY_SIZE_BYTES, r_j.key);
            }
        }

        //printf("r_j after: ");
        //for (j = 0; j < KEY_SIZE_BYTES; j++) {
        //    printf("%02x", r_j.key[j]);
        //}

        // t_2m_j = H^(2m-i)(s_1)
        for (j = 0; j < 2 * M - i; j++){
        //for (j = 0; j < 53; j++){    
            if (KEY_SIZE_BYTES == 32) {
                SHA256(t_2m_j.key, KEY_SIZE_BYTES, t_2m_j.key);
            } else if (KEY_SIZE_BYTES == 64) {
                SHA512(t_2m_j.key, KEY_SIZE_BYTES, t_2m_j.key);
            }
        }

        //xor r_j and t_2m_j to get preimage
        for (j = 0; j < KEY_SIZE_BYTES; j++) {
            preimage.key[j] = r_j.key[j] ^ t_2m_j.key[j];
        }

        //printf("\n");
        //printf("preimage: ");
        //for (j = 0; j < KEY_SIZE_BYTES; j++) {
        //    printf("%02x", preimage.key[j]);
        //}
        //commitment
        if (KEY_SIZE_BYTES == 32) {
            SHA256(preimage.key, KEY_SIZE_BYTES, commitments[i].key);
        } else if (KEY_SIZE_BYTES == 64) {
            SHA512(preimage.key, KEY_SIZE_BYTES, commitments[i].key);
        }

        
    }
    // Create Merkle Tree from commitments
    key_pair->root = create_tree(commitments, 2 * M);
//    printf("key_gen done\n");
//    printf("tree: ");
//    print_tree(key_pair->root, 10);

}

void free_memory(HBSS_key_pair *key_pair) {
    free_merkle_tree(key_pair->root);
}
void sign(unsigned char *message, HBSS_signature *signature, struct key_size_cell Seeds[2], MerkleTreeNode *root) { 
    int j;  
    int i_j;
    
    unsigned char buffer[strlen((char*) message)+ ((int)ceil(log10(DIGEST_LEN_K))+1)]; 
    HBSS_digest_message D;
    HBSS_digest_message D_j;
    SHA512(message, strlen((char*) message), D.digest_cell); 

    struct key_size_cell r_j , t_2m_j;
    struct key_size_cell preimage;

    

    for(j=0;j<DIGEST_LEN_K;j++){ 


        sprintf(buffer, "%s%d", message, j); 
        SHA512(buffer, strlen(buffer), D_j.digest_cell); 
        int i,k;
        int length_digest = DIGEST_LEN_K_BYTES;
        BIGNUM *bn = BN_new();
        BN_zero(bn);
        for (i = 0; i < length_digest; i++) {
            for(k=0; k<8; k++){
                if (D_j.digest_cell[i] >> (7-k) & 1) {
                    BN_lshift(bn, bn, 1);
                    BN_add_word(bn, 1);
                }
                else {
                    BN_lshift(bn, bn, 1);
                }
            }
        }
        BIGNUM *modolus = BN_new();
        BN_set_word(modolus, M);
        BIGNUM *result = BN_new();
        BN_zero(result);
        BN_CTX *ctx = BN_CTX_new();
        BN_mod(result, bn, modolus, ctx);
        char *dec = BN_bn2dec(result);
        char *hex_digest = BN_bn2hex(bn);
        sscanf(dec, "%d", &i_j); 
        int bit = (D.digest_cell[j/8] >> (7-(j%8))) & 1;

        memcpy(r_j.key, (Seeds)[0].key, KEY_SIZE_BYTES); // r_j = s_0
        memcpy(t_2m_j.key, (Seeds)[1].key, KEY_SIZE_BYTES); // t_2m_j = s_1

  //      printf("\n");
  //       printf("r_j: ");
  //      for (int i = 0; i < KEY_SIZE_BYTES; i++) {
  //          printf("%02x", r_j.key[i]);
  //      }


  //      printf("2*i_j + bit: %d\n", 2*i_j+bit);
  //      printf("2*M - 2*i_j - bit: %d\n", 2 * M - 2 * i_j - bit);
        // r_j = H^(2*i_j + bit )(s_0)
        for (i = 0; i < 2*i_j+bit; i++){
        //for (i = 0; i < 11; i++){
            if (KEY_SIZE_BYTES == 32) {
                SHA256(r_j.key, KEY_SIZE_BYTES, r_j.key);
            } else if (KEY_SIZE_BYTES == 64) {
                SHA512(r_j.key, KEY_SIZE_BYTES, r_j.key);
            }
        } 

    //    printf("r_j after: ");
    //    for (i = 0; i < KEY_SIZE_BYTES; i++) {
    //        printf("%02x", r_j.key[i]);
    //    }

        // t_2m_j = H^(2M-2*i_j-bit)(s_1)
        for (i = 0; i < 2 * M - 2 * i_j - bit; i++){
        //for (i = 0; i < 53; i++){
            if (KEY_SIZE_BYTES == 32) {
                SHA256(t_2m_j.key, KEY_SIZE_BYTES, t_2m_j.key);
            } else if (KEY_SIZE_BYTES == 64) {
                SHA512(t_2m_j.key, KEY_SIZE_BYTES, t_2m_j.key);
            }
        }

        //xor r_j and t_2m_j to get preimage
        for (i = 0; i < KEY_SIZE_BYTES; i++) {
            preimage.key[i] = r_j.key[i] ^ t_2m_j.key[i];
        }

    //    printf("root: ");
    //    for (i = 0; i < KEY_SIZE_BYTES; i++) {
    //        printf("%02x", root->hash.key[i]);
    //    }

    //    printf("preimage: ");
    //    for (i = 0; i < KEY_SIZE_BYTES; i++) {
    //        printf("%02x", preimage.key[i]);
    //    }
    //    printf("\n");
    //    printf("preimage number: %d\n", i_j*2+bit);


        //signature
        int path_length;
        //the path is LOG_2_2M nodes from the tree ( plus one secret, not from the path).
        struct key_size_cell path[LOG_2_2M ];
        get_path(root, 2*i_j+bit, path, &path_length);

        //printf("path_length: %d\n", path_length);
        //copy in reverse order first the preimage.key the sha of the leaf then all the sha of one child node in the end one of the root child. without the root. in total 2M-1 nodes. in total LOG_2_2M times

        // First, put preimage at the beginning
        memcpy(signature->signature[j].signature_cell, preimage.key, KEY_SIZE_BYTES);
        // Then, reverse copy the path
        //for(i=0; i<LOG_2_2M; i++){
        for(i=1; i<LOG_2_2M +1; i++){    
            memcpy(signature->signature[j].signature_cell + (i)*KEY_SIZE_BYTES, path[LOG_2_2M-i].key, KEY_SIZE_BYTES);
        }


        
        //print all the signature
    //    printf("signature: \n");
    //    for(i=0; i<LOG_2_2M+1; i++){
            //should print like the preimage for example
            //for (i = 0; i < KEY_SIZE_BYTES; i++) {
            //printf("%02x", preimage.key[i]);
           //}
    //        for(k=0; k<KEY_SIZE_BYTES; k++){
    //            printf("%02x", signature->signature[j].signature_cell[i*KEY_SIZE_BYTES+k]);                
    //        }
        
    //       printf("\n");
    //    }

        //printf("path_length: %d\n", path_length);
        //printf("log_2_2M: %d\n", LOG_2_2M);
        //check that is working. 
        //first i need hash the preimage.key in the signature[j].signature_cell , then concat and sha it with the path[i].key or signature[j].signature_cell + (i+1)*KEY_SIZE_BYTES because it is the same.
        //this is should be equal to the root value.
        
        //check if the signature is valid

        //commitment of the preimage
        //struct key_size_cell commitment;
        //if (KEY_SIZE_BYTES == 32) {
        //    SHA256(preimage.key, KEY_SIZE_BYTES, commitment.key);
        //} else if (KEY_SIZE_BYTES == 64) {
        //    SHA512(preimage.key, KEY_SIZE_BYTES, commitment.key);
        //}

        //printf("\ncommitment: ");
        //for (i = 0; i < KEY_SIZE_BYTES; i++) {
        //    printf("%02x", commitment.key[i]);
        //}

        //copy commitment to tmp to be able to concat and sha it
        //struct key_size_cell tmp;
        //memcpy(tmp.key, commitment.key, KEY_SIZE_BYTES);
        
        //for(i=0; i<LOG_2_2M-1; i++){
            //concat, try concat twice and check if whice is the correct one

        //}

        OPENSSL_free(dec);
        BN_free(bn);
        BN_free(modolus);
        BN_free(result);
        BN_CTX_free(ctx);
    }   

    //printf("signed\n");
    return 1;
    
}

void get_path(MerkleTreeNode *root, int leaf_index, struct key_size_cell *path, int *path_length) {
    //return the path for the siblings nodes. as in merkle tree.
    int i = 0,k = 0;

    //I have already the secret value, now I need the secret value sibiling, and is uncle, so on until the root (excluded).

    //level = log2(2m)

    int level = LOG_2_2M;

    *path_length = 0; // Initialize path length
    int half_number_leafs = M;
    //printf("leaf_index: %d\n", leaf_index);cc

    MerkleTreeNode *current_node = root;
    //until we reach the leaf, add the sibiling to the path
    //while (current_node->left != NULL) {
    //while (current_node != NULL) {
    while (level >0) {        
        //calculate left or right
        //printf("if leaf_index < (half_number_leafs / pow(2, i))");
        //printf("leaf_index: %d\n", leaf_index);
        //printf("half_number_leafs/pow(2, i): %d\n", half_number_leafs/pow(2, i));

        if( leaf_index < (half_number_leafs / pow(2, i)) ) {
//            printf("go to left, and take value from right child\n");
            memcpy(path[*path_length].key, current_node->right->hash.key, KEY_SIZE_BYTES);
            (*path_length)++;            
            current_node = current_node->left;
            
        } else {
            //right
 //           printf("go to right, and take value from left child\n");
            memcpy(path[*path_length].key, current_node->left->hash.key, KEY_SIZE_BYTES);
            (*path_length)++;
            current_node = current_node->right;
            leaf_index -= (half_number_leafs / pow(2, i));
        }
        i++;
        level--;
        //printf("i: %d\n", i);
        //print all the nodes in the path from the merkle tree

        //printf("current_node: ");
        //for (k = 0; k < KEY_SIZE_BYTES; k++) {
        //    printf("%02x", current_node->hash.key[k]);
        //}
        //printf("\n");
        //printf("current_node number: %d\n", current_node->number);

    }
//    printf("\n");
}

int verify(unsigned char *message, HBSS_signature *signature, MerkleTreeNode *root ) {

//    printf("verify\n");
//    printf("message: %s\n", message);

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
        int i,k;
        int length_digest = DIGEST_LEN_K_BYTES;
        BIGNUM *bn = BN_new();
        BN_zero(bn);
        for (i = 0; i < length_digest; i++) {
            for(k=0; k<8; k++){
                if (D_j.digest_cell[i] >> (7-k) & 1) {
                    BN_lshift(bn, bn, 1);
                    BN_add_word(bn, 1);
                }
                else {
                    BN_lshift(bn, bn, 1);
                }
            }
        }
        BIGNUM *modolus = BN_new();
        BN_set_word(modolus, M);
        BIGNUM *result = BN_new();
        BN_zero(result);
        BN_CTX *ctx = BN_CTX_new();
        BN_mod(result, bn, modolus, ctx);
        char *dec = BN_bn2dec(result);
        sscanf(dec, "%d", &i_j); 
        int bit = (D.digest_cell[j/8] >> (7-(j%8))) & 1;        
        //the preimage number 2*i_j+bit

        int preimage_number = 2*i_j+bit;
        //int preimage_number = 11;


        //checking the path of the signature is correct by xor path and see if it match the root.
        struct key_size_cell sha_to_the_root;
        struct key_size_cell tmp;

        //CONCAT
        struct key_size_cell concat[2];

        //the first element of the path is the sha_to_the_root
        memcpy(sha_to_the_root.key, signature->signature[j].signature_cell, KEY_SIZE_BYTES);

//        printf("preimage: ");
//        for (k = 0; k < KEY_SIZE_BYTES; k++) {
//            printf("%02x", sha_to_the_root.key[k]);
//        }

        //SHA256 preimage to get the root
        if (KEY_SIZE_BYTES == 32) {
            SHA256(sha_to_the_root.key, KEY_SIZE_BYTES, sha_to_the_root.key);
        } else if (KEY_SIZE_BYTES == 64) {
            SHA512(sha_to_the_root.key, KEY_SIZE_BYTES, sha_to_the_root.key);
        }

//        printf("hash of preimage: ");
//        for (k = 0; k < KEY_SIZE_BYTES; k++) {
//            printf("%02x", sha_to_the_root.key[k]);
//        }

        for (i = 1; i < LOG_2_2M +1; i++) {
            //take value from the signature 

            memcpy(tmp.key, signature->signature[j].signature_cell + (i)*KEY_SIZE_BYTES, KEY_SIZE_BYTES);
            //based of the number of the preimage, xor it right or left with the sha_to_the_root
            //calculate left or right, take the last bit of the preimage (2*i_j+bit)

//            printf("signature tmp: ");
//            for (k = 0; k < KEY_SIZE_BYTES; k++) {
//                printf("%02x", tmp.key[k]);
//            }

            //i dont need to know where is location, i think i need to know where i placed compare to the corrent value.
            int last_bit = preimage_number & 1;

//            printf("last_bit: %d\n", last_bit);
//            printf("preimage_number: %d\n", preimage_number);
            //first i have the hash of secret. after it i have his sibiling.  if the sercet is even, means that he on the right side, and his sibiling on the left side.


            //printf("left or right: \n");
            if (last_bit == 0) {
                //secret in left side, the sibiling from right
//                printf("secret in left side, the sibiling from right \n");
                //sha the concat of the sha_to_the_root.key || tmp.key
                
                memcpy(concat[0].key, sha_to_the_root.key, KEY_SIZE_BYTES);
                memcpy(concat[1].key, tmp.key, KEY_SIZE_BYTES);

                if (KEY_SIZE_BYTES == 32) {
                    SHA256(concat, 2*KEY_SIZE_BYTES, sha_to_the_root.key);
                } else if (KEY_SIZE_BYTES == 64) {
                    SHA512(concat, 2*KEY_SIZE_BYTES, sha_to_the_root.key);
                }


            } else {
                //secret in right side, the sibiling from left
 //               printf("secret in right side, the sibiling from left \n");
                //xor(tmp.key, sha_to_the_root.key, sha_to_the_root.key, KEY_SIZE_BYTES);

                memcpy(concat[0].key, tmp.key, KEY_SIZE_BYTES);
                memcpy(concat[1].key, sha_to_the_root.key, KEY_SIZE_BYTES);

                if (KEY_SIZE_BYTES == 32) {
                    SHA256(concat, 2*KEY_SIZE_BYTES, sha_to_the_root.key);
                } else if (KEY_SIZE_BYTES == 64) {
                    SHA512(concat, 2*KEY_SIZE_BYTES, sha_to_the_root.key);
                }
            }

//            printf("sha_to_the_root: ");
//            for (k = 0; k < KEY_SIZE_BYTES; k++) {
//                printf("%02x", sha_to_the_root.key[k]);
//            }
            //divide the preimage by 2
            preimage_number = preimage_number >> 1;
        }

        //check if the root is the same as the root we got from the signature , if not return error.
        if (memcmp(sha_to_the_root.key, root->hash.key, KEY_SIZE_BYTES) != 0) {
            printf("error in root\n");
            return 0;
        }


        //if(KEY_SIZE_BYTES == 32){
        //    SHA256(signature->signature[j].signature_cell, KEY_SIZE/8, D_sign_j.digest_cell);         
        //}
        //else if(KEY_SIZE_BYTES == 64){
        //    SHA512(signature->signature[j].signature_cell, KEY_SIZE/8, D_sign_j.digest_cell);         
        //}


        //if(memcmp(D_sign_j.digest_cell, Commitment[2*i_j+bit].key, KEY_SIZE/8) != 0){    
        //        exit(EXIT_FAILURE);
        //    }
        
        
        OPENSSL_free(dec);
        BN_free(bn);
        BN_free(modolus);
        BN_free(result);
        BN_CTX_free(ctx);

//        printf("\n");
    }
//    printf("verified\n");
    return 1;
}

//    for(j=0;j<DIGEST_LEN_K;j++){         
//       
//        //checking the path of the signature is correct by xor path and see if it match the root.
//        struct key_size_cell xor_to_the_root;
//        struct key_size_cell tmp;
//
//        //the first element of the path is the xor_to_the_root
//        memcpy(xor_to_the_root.key, signature->signature[j].signature_cell, KEY_SIZE_BYTES);
//
//        //SHA256 preimage to get the root
//        if (KEY_SIZE_BYTES == 32) {
//            SHA256(xor_to_the_root.key, KEY_SIZE_BYTES, xor_to_the_root.key);
//        } else if (KEY_SIZE_BYTES == 64) {
//            SHA512(xor_to_the_root.key, KEY_SIZE_BYTES, xor_to_the_root.key);
//       }
//
//       //for every value in the path for the root, we xor it with the xor_to_the_root, log_2(2M) times. we need get the root.
//
//        for (i = 0; i < LOG_2_2M; i++) {
//            //take value from the path 
//            memcpy(tmp.key, signature->signature[j].signature_cell + (i+1)*KEY_SIZE_BYTES, KEY_SIZE_BYTES);
//            //xor it with xor_to_the_root
//            xor(xor_to_the_root.key, tmp.key, xor_to_the_root.key, KEY_SIZE_BYTES);
//        }
//
//        //check if the root is the same as the root we got from the signature , if not return error.
//        if (memcmp(xor_to_the_root.key, root->hash.key, KEY_SIZE_BYTES) != 0) {
//            printf("error in root\n");
//            return 0;
//        }
//    }
//}

void xor(unsigned char* a, unsigned char* b, unsigned char* out, int len) {
    for (int i = 0; i < len; i++) {
        out[i] = a[i] ^ b[i];
    }
}



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

    // Process the right child first
    print_tree(node->right, depth + 1);

    // Print the current node
    for(int i = 0; i < depth; i++)
        printf("\t"); // Use a tab to indent the node based on its depth in the tree

    // Print the value of the key
    for(int i = 0; i < KEY_SIZE_BYTES; i++)
        printf("%02X", node->hash.key[i]);
    printf("\n");

    // Process the left child
    print_tree(node->left, depth + 1);
}