#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "cycles.h"
#include "hbss.h"

static void printfcomma(unsigned long long n)
{
    if (n >= 1000) {
        printf(",%llu", n);
        return;
    } 
    printfcomma(n / 1000);
    printf("%03llu", n % 1000);
}

static void printfalignedcomma(unsigned long long n, int len)
{
    unsigned long long ncopy = n;
    int i = 0;

    while (ncopy > 9) {
        len -= 1;
        ncopy /= 10;
        i += 1;
    }
    i = i/3 - 1;
    for (; i < len; i++) {
        printf(" ");
    }
    printfcomma(n);
}

static void display_result(double result, unsigned long long *l)
{
    printf("Time taken: %11.2lf us (%2.2lf sec); Cycles: ", result, result / 1e6);
    printfalignedcomma(l[1] - l[0], 12);
    printf(" cycles\n");
}

#define MEASURE_GENERIC(TEXT, FNCALL)\
    printf(TEXT);\
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);\
    t[0] = cpucycles();\
    FNCALL;\
    t[1] = cpucycles();\
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stop);\
    result = ((stop.tv_sec - start.tv_sec) * 1e6 + (stop.tv_nsec - start.tv_nsec) / 1e3);\
    display_result(result, t);

#define MEASURE(TEXT, FNCALL) MEASURE_GENERIC(TEXT, FNCALL)

int main()
{

    HBSS_key_pair key_pair;
    HBSS_signature signature;

    unsigned char *message;

    if (RANDOM_MESSAGE_SIZE == 0) {
        message = malloc(1); 
        message[0] = '\0'; 
    }
    else {
        message = malloc(RANDOM_MESSAGE_SIZE);
        RAND_bytes(message, RANDOM_MESSAGE_SIZE);
    }

    struct timespec start, stop;
    double result;
    unsigned long long t[2];

    setbuf(stdout, NULL);
    init_cpucycles();

    printf("Parameters: M = %d, KEY_SIZE = %d, KEY_SIZE_BYTES = %d, DIGEST_LEN_K = %d, DIGEST_LEN_K_BYTES = %d, N_SIGNATURES_TOTAL = %d , RANDOM_MESSAGE_SIZE = %d , STEP = %d \n", M, KEY_SIZE, KEY_SIZE_BYTES, DIGEST_LEN_K, DIGEST_LEN_K_BYTES, N_SIGNATURES_TOTAL, RANDOM_MESSAGE_SIZE, STEP);

    MEASURE("Generate key pair...   ", key_gen(&key_pair));
    MEASURE("Sign message...        ", sign(message, &signature, key_pair.Seeds));
    MEASURE("Verify signature...    ", verify(message, &signature, key_pair.Commitment));
    
    free_memory(&key_pair);
    free(message);

    return 0;
}

