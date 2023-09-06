#include "hbss.h"

void key_gen(HBSS_key_pair *key_pair) {

    RAND_bytes(key_pair->Seeds[0].key, KEY_SIZE_BYTES); // random key
    RAND_bytes(key_pair->Seeds[1].key, KEY_SIZE_BYTES); // random key

    int i, j;

    struct key_size_cell r_j , t_2m_j;
    struct key_size_cell preimage;

    key_pair->Commitment = malloc(2 * M * sizeof(struct key_size_cell));

    for (i = 0; i < 2 * M; i++) {
        memcpy(r_j.key, key_pair->Seeds[0].key, KEY_SIZE_BYTES); // r_j = s_0
        memcpy(t_2m_j.key, key_pair->Seeds[1].key, KEY_SIZE_BYTES); // t_2m_j = s_1

        // r_j = H^i(s_0)
        for (j = 0; j <=i; j++){
            if (KEY_SIZE_BYTES == 32) {
                SHA256(r_j.key, KEY_SIZE_BYTES, r_j.key);
            } else if (KEY_SIZE_BYTES == 64) {
                SHA512(r_j.key, KEY_SIZE_BYTES, r_j.key);
            }
        }

        // t_2m_j = H^(2m-i)(s_1)
        for (j = 0; j <= 2 * M - i; j++){
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

        //commitment
        if (KEY_SIZE_BYTES == 32) {
            SHA256(preimage.key, KEY_SIZE_BYTES, key_pair->Commitment[i].key);
        } else if (KEY_SIZE_BYTES == 64) {
            SHA512(preimage.key, KEY_SIZE_BYTES, key_pair->Commitment[i].key);
        }

    }
}

void free_memory(HBSS_key_pair *key_pair) {
    free(key_pair->Commitment);
}
void sign(unsigned char *message, HBSS_signature *signature, struct key_size_cell (*Seeds)[2]) { 
    int j;  
    int i_j;
    
    unsigned char buffer[strlen((char*) message)+ ((int)ceil(log10(DIGEST_LEN_K))+1)]; 
    HBSS_digest_message D;
    HBSS_digest_message D_j;
    SHA512(message, strlen((char*) message), D.digest_cell); 

    struct key_size_cell r_j , t_2m_j;
    struct key_size_cell preimage;

    for(j=0;j<DIGEST_LEN_K;j++){ 

        memcpy(r_j.key, (*Seeds)[0].key, KEY_SIZE_BYTES); // r_j = s_0
        memcpy(t_2m_j.key, (*Seeds)[1].key, KEY_SIZE_BYTES); // t_2m_j = s_1

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

        // r_j = H^(2*i_j + bit )(s_0)
        for (i = 0; i <=2*i_j+bit; i++){
            if (KEY_SIZE_BYTES == 32) {
                SHA256(r_j.key, KEY_SIZE_BYTES, r_j.key);
            } else if (KEY_SIZE_BYTES == 64) {
                SHA512(r_j.key, KEY_SIZE_BYTES, r_j.key);
            }
        }

        // t_2m_j = H^(2M-2*i_j-bit)(s_1)
        for (i = 0; i <= 2 * M - 2 * i_j - bit; i++){
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

        //signature
        memcpy(signature->signature[j].signature_cell, preimage.key, KEY_SIZE_BYTES);

        OPENSSL_free(dec);
        BN_free(bn);
        BN_free(modolus);
        BN_free(result);
        BN_CTX_free(ctx);
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
        
        if(KEY_SIZE_BYTES == 32){
            SHA256(signature->signature[j].signature_cell, KEY_SIZE/8, D_sign_j.digest_cell);         
        }
        else if(KEY_SIZE_BYTES == 64){
            SHA512(signature->signature[j].signature_cell, KEY_SIZE/8, D_sign_j.digest_cell);         
        }
        
        int bit = (D.digest_cell[j/8] >> (7-(j%8))) & 1;
        if(memcmp(D_sign_j.digest_cell, Commitment[2*i_j+bit].key, KEY_SIZE/8) != 0){    
                exit(EXIT_FAILURE);
            }
        OPENSSL_free(dec);
        BN_free(bn);
        BN_free(modolus);
        BN_free(result);
        BN_CTX_free(ctx);
    }
    return 1;
}

