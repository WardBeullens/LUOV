#include "LUOV.h"

#ifdef KAT
	#define printIntermediateValue(A) printf(A)
#else
	#define printIntermediateValue(A) 
#endif

/*
	Generates a new keypair

	pk : char array that receives the new public key
	sk : char array that receives the new secret key
*/
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk) 
{
	printIntermediateValue("--- Start keygen ---\n");
	
#ifdef PRECOMPUTE
	unsigned char *small_pk = aligned_alloc(32,PUBLIC_KEY_BYTES);
	luov_generateBigKeyPair(small_pk , pk , sk);
	free(small_pk);
#else
	luov_generateKeyPair(pk , sk);
#endif
	
	printIntermediateValue("--- End keygen ---\n");
	return 0;
}

/*
	Signs a document

	sm : char array that receives the signed message
	smlen : receives the length of the signed message
	m  : char array that contains the original message
	mlen : length of original message
	sk : char array containing the secret key
*/
int crypto_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *m, unsigned long long mlen, const unsigned char *sk)
{
	printIntermediateValue("--- Start signing ---\n");

	// Produce a signature
#ifdef PRECOMPUTE
	luov_sign_fast(sm, smlen, m , mlen, sk);
#else
	luov_sign(sm , smlen, m, mlen, sk);
#endif

	printIntermediateValue("--- End signing ---\n");
	return 0;
}

/*
	Verify a signature

	m :  char array that receives the original message
	mlen : receives the length of the original message
	sm : char array that contains the signed message
	smlen : the length of the signed message
	pk : char array containing the public key

	returns : 0 if the signature is accepted, -1 otherwise
*/
int crypto_sign_open(unsigned char *m, unsigned long long *mlen, const unsigned char *sm, unsigned long long smlen, const unsigned char *pk)
{
	int valid;
	
	printIntermediateValue("--- Start verifying ---\n");
	
	// Verify signature
#ifdef PRECOMPUTE
	valid = luov_verify_fast(pk, sm , smlen, m, mlen);
#else
	valid = luov_verify(pk, sm, smlen, m, mlen);
#endif
	
	printIntermediateValue("--- End verifying ---\n");
	return valid;
}
