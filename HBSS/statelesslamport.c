#include "statelesslamport.h"

void key_gen(stateless_lamport_key_pair *key_pair) {
    int i;
    key_pair->secret_key = malloc(2 * sizeof(struct key_size_cell *));
    key_pair->public_key = malloc(2 * sizeof(struct key_size_cell *));
    for (i = 0; i < 2; i++) {
        key_pair->secret_key[i] = malloc(M * sizeof(struct key_size_cell));
        key_pair->public_key[i] = malloc(M * sizeof(struct key_size_cell));
    }
    for (i = 0; i < M; i++) {
        RAND_bytes(key_pair->secret_key[0][i].key, KEY_SIZE_BYTES);
        RAND_bytes(key_pair->secret_key[1][i].key, KEY_SIZE_BYTES);
        
        SHA256(key_pair->secret_key[0][i].key, KEY_SIZE_BYTES, key_pair->public_key[0][i].key);
        SHA256(key_pair->secret_key[1][i].key, KEY_SIZE_BYTES, key_pair->public_key[1][i].key);        
    }
}

void free_memory(stateless_lamport_key_pair *key_pair) {
    int i;
    // Deallocate memory for the arrays
    for (i = 0; i < 2; i++) {
        free(key_pair->secret_key[i]);
        free(key_pair->public_key[i]);
    }
    free(key_pair->secret_key);
    free(key_pair->public_key);
}

void sign(unsigned char *message, stateless_lamport_signature *signature, struct key_size_cell **secret_key) {    
    int j;  // maybe this should be smaller than 32 bits
    int i_j; // this number we be smaller then M, check if i can make it smaller than 32 bits
    
    unsigned char buffer[strlen((char*) message)+ ((int)ceil(log10(DIGEST_LEN_K))+1)]; //check if this is the right size. check if it is work as expected. //calculate in DEFINE the number that sould be us for 512.0
    stateless_lamport_digest_message D;
    stateless_lamport_digest_message D_j;
    SHA512(message, strlen((char*) message), D.digest_cell); //calculate the digest of the message
    for(j=0;j<DIGEST_LEN_K;j++){ //loop over the bits in the digest
        sprintf(buffer, "%s%d", message, j); //concatenate the message with the j

        SHA512(buffer, strlen(buffer), D_j.digest_cell); //calculate the digest of the message with j

        
        union { // providing for up to N = 64bits (on my system)
            unsigned char c[8];
            unsigned long i_j;
        } mod;

        mod.i_j = 0; // initialise

        size_t sz = sizeof D_j.digest_cell / sizeof D_j.digest_cell[0]; // source byte count
        size_t n = 0; // destination byte count

        for( size_t i = sz; i && n < sizeof mod; ) {
            mod.c[ n++ ] = D_j.digest_cell[ --i ]; // grab one byte
        }

        int N = LEN_M;
        mod.i_j &= (1<<N)-1; // Mask off the low order N bits from that long

        int bit = (D.digest_cell[j/8] >> (7-(j%8))) & 1;

        if (bit == 1) {
            memcpy(signature->signature[j].signature_cell, secret_key[1][mod.i_j].key, KEY_SIZE_BYTES);
        } else if (bit == 0) {
            memcpy(signature->signature[j].signature_cell, secret_key[0][mod.i_j].key, KEY_SIZE_BYTES);
        }
    }   

    return 1;
}

int verify(unsigned char *message, stateless_lamport_signature *signature, struct key_size_cell **public_key ) {
    int j;  
    int i_j; 
    unsigned char buffer[strlen((char*) message)+((int)ceil(log10(DIGEST_LEN_K))+1)];
    stateless_lamport_digest_message D;
    stateless_lamport_digest_message D_j;
    stateless_lamport_digest_signature D_sign_j;
    SHA512(message, strlen((char*) message), D.digest_cell); 
    for(j=0;j<DIGEST_LEN_K;j++){ //loop over the bits in the digest
        sprintf(buffer, "%s%d", message, j); //concatenate the message with the j
        SHA512(buffer, strlen(buffer), D_j.digest_cell); //calculate the digest of the message
 
        union { // providing for up to N = 64bits (on my system)
            unsigned char c[8];
            unsigned long i_j;
        } mod;

        mod.i_j = 0; // initialise

        size_t sz = sizeof D_j.digest_cell / sizeof D_j.digest_cell[0]; // source byte count
        size_t n = 0; // destination byte count

        for( size_t i = sz; i && n < sizeof mod; ) {
            mod.c[ n++ ] = D_j.digest_cell[ --i ]; // grab one byte
        }

        int N = LEN_M;
        mod.i_j &= (1<<N)-1; // Mask off the low order N bits from that long

        SHA256(signature->signature[j].signature_cell, KEY_SIZE/8, D_sign_j.digest_cell); //calculate the digest of the signature        
        
        int bit = (D.digest_cell[j/8] >> (7-(j%8))) & 1;
        if(bit == 1){
            if(memcmp(D_sign_j.digest_cell, public_key[1][mod.i_j].key, KEY_SIZE/8) != 0){    
                printf("error in signture\n");
                return 0;
            }
        } else if (bit == 0) {
            if(memcmp(D_sign_j.digest_cell, public_key[0][mod.i_j].key, KEY_SIZE/8) != 0){
                printf("error in signture\n");
                return 0;
            }
        }

    }
    return 1;
}

