#include "hbss.h"

void key_gen(HBSS_key_pair *key_pair) {

    struct key_size_cell hash0, hash1;
    struct key_size_cell preimage;

    struct key_size_cell hash0_array[STEP];
    struct key_size_cell hash1_array[STEP];
    
    key_pair->Seeds = malloc(2 * sizeof(struct key_size_cell *));
    key_pair->Commitment = malloc(2 * M * sizeof(struct key_size_cell));
    for (size_t i = 0; i < 2; i++) {
        key_pair->Seeds[i] = malloc(2*M/STEP * sizeof(struct key_size_cell));
    }

    RAND_bytes(key_pair->Seeds[0][0].key, KEY_SIZE_BYTES);
    RAND_bytes(key_pair->Seeds[1][0].key, KEY_SIZE_BYTES);

    for (size_t i = 0; i < 2*M/STEP - 1; i++) {
        memcpy(hash0.key, key_pair->Seeds[0][i].key, KEY_SIZE_BYTES);
        memcpy(hash1.key, key_pair->Seeds[1][i].key, KEY_SIZE_BYTES);

        for (size_t j = 0; j < STEP; j++) {
            SHA256(hash0.key, KEY_SIZE_BYTES, hash0.key);
            SHA256(hash1.key, KEY_SIZE_BYTES, hash1.key);
        }

        memcpy(key_pair->Seeds[0][i+1].key, hash0.key, KEY_SIZE_BYTES);
        memcpy(key_pair->Seeds[1][i+1].key, hash1.key, KEY_SIZE_BYTES);    
    }
    
    for (size_t i = 0; i < 2*M/STEP; i++) {

        memcpy(hash0_array[0].key, key_pair->Seeds[0][i].key, KEY_SIZE_BYTES);
        memcpy(hash1_array[0].key, key_pair->Seeds[1][2*M/STEP - 1 - i].key, KEY_SIZE_BYTES);

        for (size_t j = 0; j < STEP-1; j++) {
            SHA256(hash0_array[j].key, KEY_SIZE_BYTES, hash0_array[j+1].key);
            SHA256(hash1_array[j].key, KEY_SIZE_BYTES, hash1_array[j+1].key);
        }

        for (size_t j = 0; j < STEP; j++) {
            for (size_t k = 0; k < KEY_SIZE_BYTES; k++) {
                preimage.key[k] = hash0_array[j].key[k] ^ hash1_array[STEP-j-1].key[k];
            }
            SHA256(preimage.key, KEY_SIZE_BYTES, key_pair->Commitment[j+i*STEP].key);
        }
    
    }
}

void free_memory(HBSS_key_pair *key_pair) {
    free(key_pair->Commitment);
    for (size_t i = 0; i < 2; i++) {
        free(key_pair->Seeds[i]);
    }
    free(key_pair->Seeds);
}

void sign(unsigned char *message, HBSS_signature *signature, struct key_size_cell **Seeds) { 
    int j;  
    int i_j;
    
    unsigned char buffer[strlen((char*) message)+ ((int)ceil(log10(DIGEST_LEN_K))+1)]; 
    HBSS_digest_message D;
    HBSS_digest_message D_j;
    SHA512(message, strlen((char*) message), D.digest_cell); 

    struct key_size_cell hash0, hash1;
    struct key_size_cell preimage;

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

        int block_step0 = 2*mod.i_j/STEP;
        memcpy(hash0.key, Seeds[0][block_step0].key, KEY_SIZE_BYTES);
        memcpy(hash1.key, Seeds[1][2*M/STEP-block_step0-1].key, KEY_SIZE_BYTES);

        int step0 = (2*mod.i_j+bit) & (STEP - 1);
        int step1 = STEP - step0 - 1;
        
        for (size_t k = 0; k < step0; k++) {
            SHA256(hash0.key, KEY_SIZE_BYTES, hash0.key);
        }            

        for (size_t k = 0; k < step1; k++) {
            SHA256(hash1.key, KEY_SIZE_BYTES, hash1.key);
        }

        for (size_t k = 0; k < KEY_SIZE_BYTES; k++) {
            preimage.key[k] = hash0.key[k] ^ hash1.key[k];
        }
        memcpy(signature->signature[j].signature_cell, preimage.key, KEY_SIZE_BYTES);
    }   
}

int verify(unsigned char *message, HBSS_signature *signature, struct key_size_cell *Commitment ) {
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
        
        SHA256(signature->signature[j].signature_cell, KEY_SIZE/8, D_sign_j.digest_cell);         

        int bit = (D.digest_cell[j/8] >> (7-(j%8))) & 1;
        if(memcmp(D_sign_j.digest_cell, Commitment[2*mod.i_j+bit].key, KEY_SIZE/8) != 0){  
                printf("Verification failed\n");  
                exit(EXIT_FAILURE);
            }
    }
    return 1;
}

