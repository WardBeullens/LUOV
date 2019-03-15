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
#include "ColumnGenerator.h"

#define PK_SEED(pk) pk
#define PK_Q2(pk) (pk + 32)

#define SIG_SOL(sig) sig
#define SIG_SALT(sig) (sig+ VARS*(FIELD_SIZE/8) )

#define PARTSIG_INVERSE(partial_signature) (partial_signature) 
#define PARTSIG_VINEGAR(partial_signature) (PARTSIG_INVERSE(partial_signature) + (OIL_VARS*FIELD_SIZE/8+7)/8*8*OIL_VARS*(FIELD_SIZE))
#define PARTSIG_TARGET(partial_signature) (PARTSIG_VINEGAR(partial_signature) + (FIELD_SIZE/8)*VINEGAR_VARS )
#define PARTSIG_T(partial_signature) (PARTSIG_TARGET(partial_signature) + (FIELD_SIZE/8)*OIL_VARS  )
#define PARTSIG_SALT(partial_signature) (PARTSIG_T(partial_signature) + sizeof(column)*(VINEGAR_VARS+1) )


int luov_keygen(unsigned char *pk, unsigned char *sk);
int luov_sign(unsigned char *sig, unsigned long long * smlen, const unsigned char* document, uint64_t len, const unsigned char *sk);
int luov_verify(unsigned char* m, unsigned long long *mlen, const unsigned char* sm, unsigned long long smlen, const unsigned char *pk);

int luov_sign_start(unsigned char *partial_signature, const unsigned char *sk);
int luov_sign_finish(unsigned char *sig, unsigned long long * smlen, const unsigned char* document, uint64_t len, unsigned char *partial_signature);

#endif 
