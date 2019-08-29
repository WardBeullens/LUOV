#ifndef API_H
#define API_H

#include "parameters.h"
#include "LUOV.h"

/* Number of bytes it takes to encode the secret key */
#define CRYPTO_SECRETKEYBYTES ( 32 )                                   
/* Number of bytes it takes to encode the public key */
#define CRYPTO_PUBLICKEYBYTES ( 32 + ((STORED_COLS_OF_P*OIL_VARS+7)/8) )  
/* Number of bytes it takes to encode a signature */
#define CRYPTO_BYTES ( (VARS*FIELD_SIZE + 7) /8  + SALT_BYTES )  
/* Number of bytes it takes to encode a partial signature */
#define _PARTIAL_SIGNATURE_BYTES ( VARS*(sizeof(FELT)) + (OIL_VARS*sizeof(FELT)+7)/8*8*OIL_VARS*(FIELD_SIZE) + sizeof(column)*(VINEGAR_VARS+1) + SALT_BYTES )                        
#define PARTIAL_SIGNATURE_BYTES ((_PARTIAL_SIGNATURE_BYTES+7)/8*8)

#define CRYPTO_ALGNAME "LUOV"

#define crypto_sign_keypair luov_keygen
#define crypto_sign luov_sign
#define crypto_sign_open luov_verify

#endif 
