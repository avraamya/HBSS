#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "cycles.h"
#include "hbss.h"

static int cmp_llu(const void *a, const void*b)
{
  if(*(unsigned long long *)a < *(unsigned long long *)b) return -1;
  if(*(unsigned long long *)a > *(unsigned long long *)b) return 1;
  return 0;
}

static unsigned long long median(unsigned long long *l, size_t llen)
{
  qsort(l,llen,sizeof(unsigned long long),cmp_llu);

  if(llen%2) return l[llen/2];
  else return (l[llen/2-1]+l[llen/2])/2;
}

static void delta(unsigned long long *l, size_t llen)
{
    unsigned int i;
    for(i = 0; i < llen - 1; i++) {
        l[i] = l[i+1] - l[i];
    }
}

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

static void display_result(double result, unsigned long long *l, size_t llen, unsigned long long mul)
{
    unsigned long long med;

    result /= 1;
    delta(l, 1 + 1);
    med = median(l, llen);
    printf("avg. %11.2lf us (%2.2lf sec); median ", result, result / 1e6);
    printfalignedcomma(med, 12);
    printf(" cycles,  %5llux: ", mul);
    printfalignedcomma(mul*med, 12);
    printf(" cycles\n");
}

#define MEASURE_GENERIC(TEXT, MUL, FNCALL, CORR)\
    printf(TEXT);\
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);\
    for(i = 0; i < 1; i++) {\
        t[i] = cpucycles() / CORR;\
        FNCALL;\
    }\
    t[1] = cpucycles();\
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stop);\
    result = ((stop.tv_sec - start.tv_sec) * 1e6 + \
        (stop.tv_nsec - start.tv_nsec) / 1e3) / (double)CORR;\
    display_result(result, t, 1, MUL);
#define MEASURT(TEXT, MUL, FNCALL)\
    MEASURE_GENERIC(\
        TEXT, MUL,\
        do {\
          for (int j = 0; j < 1000; j++) {\
            FNCALL;\
          }\
        } while (0);,\
    1000);
#define MEASURE(TEXT, MUL, FNCALL) MEASURE_GENERIC(TEXT, MUL, FNCALL, 1)


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
    unsigned long long t[1 + 1];
    int i;

    setbuf(stdout, NULL);
    init_cpucycles();

    printf("Parameters: M = %d, KEY_SIZE = %d, KEY_SIZE_BYTES = %d, DIGEST_LEN_K = %d, DIGEST_LEN_K_BYTES = %d, N_SIGNATURES_TOTAL = %d , RANDOM_MESSAGE_SIZE = %d \n", M, KEY_SIZE, KEY_SIZE_BYTES, DIGEST_LEN_K, DIGEST_LEN_K_BYTES, N_SIGNATURES_TOTAL, RANDOM_MESSAGE_SIZE);

   
   
    MEASURE("Generate key pair...   ", 1, key_gen(&key_pair));
    MEASURE("Sign message...        ", N_SIGNATURES_TOTAL, sign(message, &signature, key_pair.secret_key, key_pair.tree));
    MEASURE("Verify signature...    ", N_SIGNATURES_TOTAL, verify(message, &signature, key_pair.tree->hash));
    

    //test
    //key_gen(&key_pair);
    //sign(message, &signature, key_pair.secret_key, key_pair.tree)
    //verify(message, &signature, key_pair.root);

    free_memory(&key_pair);
    free(message);

    return 0;
}

