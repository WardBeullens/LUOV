#ifndef LUOV_H
#define LUOV_H

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "parameters.h"
#include "Column.h"
#include "LinearAlgebra.h"
#include "rng.h"
#include "buffer.h"
#include "prng.h"
#include "api.h"
#include "intermediateValues.h"

#define PK_SEED(pk) pk
#define PK_Q2(pk) (pk + 32)

#define SIG_SOL(sig) sig
#define SIG_SALT(sig) (sig+ (VARS*FIELD_SIZE+7)/8  )

int luov_keygen(unsigned char *pk, unsigned char *sk);
int luov_sign(unsigned char *sig, unsigned long long * smlen, const unsigned char* document, uint64_t len, const unsigned char *sk);
int luov_verify(unsigned char* m, unsigned long long *mlen, const unsigned char* sm, unsigned long long smlen, const unsigned char *pk);

#endif 
