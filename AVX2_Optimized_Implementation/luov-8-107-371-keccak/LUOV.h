#ifndef LUOV_H
#define LUOV_H

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "immintrin.h"
#include <stdint.h>
#include <string.h>
#include <stdalign.h>

#include "parameters.h"
#include "LinearAlgebra.h"
#include "randombytes.h"
#include "keccakrng.h"
#include "api.h"
#include "intermediateValues.h"

void* aligned_alloc(size_t, size_t);

void luov__sign(unsigned char *sm, unsigned long long *smlen , const unsigned char* m, uint64_t mlen, const unsigned char *sk, int fast);

void luov_generateKeyPair(unsigned char *pk, unsigned char *sk);
int luov_verify(const unsigned char *pk, const unsigned char *sm, const unsigned long long smlen , unsigned char* m, unsigned long long *mlen);
#define luov_sign(sm,smlen,m,mlen,sk) luov__sign(sm,smlen,m,mlen,sk,0)

void luov_generateBigKeyPair(unsigned char *pk, unsigned char *big_pk, unsigned char *big_sk);
void luov_precompute_sign(unsigned char *big_sk, const unsigned char *sk);
#define luov_sign_fast(sm,smlen,m,mlen,sk) luov__sign(sm,smlen,m,mlen,sk,1)
void luov_precompute_verify(unsigned char *big_pk , const unsigned char *pk);
int luov_verify_fast(const unsigned char *big_pk , const unsigned char *sm, const unsigned long long smlen , unsigned char* m, unsigned long long *mlen);

#endif 
