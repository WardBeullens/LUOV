#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#include "parameters.h"

#include "LUOV.h"

#include "api.h"
#include <stdlib.h>

#define NUMBER_OF_KEYPAIRS 10      /* Number of keypairs that is generated during test */
#define SIGNATURES_PER_KEYPAIR 100  /* Number of times each keypair is used to sign a random document, and verify the signature */

//used for timing stuff
static inline
uint64_t rdtsc(){
    unsigned int lo,hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}
#define TIC printf("\n"); uint64_t cl = rdtsc();
#define TOC(A) printf("%s cycles = %llu \n",#A ,rdtsc() - cl); cl = rdtsc();

/*
	Tests the execution of the keypair generation, signature generation and signature verification algorithms and prints timing results
*/
int main(void)
{
	int i, j, k;
	int message_size = 100;
	unsigned long long smlen;
	unsigned char m[message_size];
	unsigned char m2[message_size];
	unsigned char *pk = malloc(sizeof(unsigned char[CRYPTO_PUBLICKEYBYTES]));
	unsigned char *sk = malloc(sizeof(unsigned char[CRYPTO_SECRETKEYBYTES]));
	unsigned char *_partial_signature = malloc(sizeof(unsigned char[PARTIAL_SIGNATURE_BYTES+7]));
	unsigned char *partial_signature = _partial_signature + (((uint64_t) _partial_signature)&7);
	unsigned char *sm = malloc(sizeof(unsigned char[message_size + CRYPTO_BYTES]));
	clock_t cl;

	// Print key and signature sizes
	printf("Public Key takes %d B\n", CRYPTO_PUBLICKEYBYTES );
	printf("Secret Key takes %d B\n", CRYPTO_SECRETKEYBYTES );
	printf("Partial signature takes %ld B\n", PARTIAL_SIGNATURE_BYTES );
	printf("Signature takes %d B\n\n", CRYPTO_BYTES );

	srand((unsigned int) time(NULL));

	uint64_t keygen_cyc = 0;
	uint64_t sign_start_cyc = 0;
	uint64_t sign_finish_cyc = 0;
	uint64_t verify_cyc = 0;
	uint64_t cycles = 0;

	for (i = 0; i < NUMBER_OF_KEYPAIRS ; i++) {

		// time key pair generation
		cycles = rdtsc();
		crypto_sign_keypair(pk, sk);
		keygen_cyc += rdtsc()-cycles;

		for (j = 0; j < SIGNATURES_PER_KEYPAIR ; j++) {
			
			// pick a random message to sign
			for (k = 0; k < message_size; k++) {
				m[k] = ((unsigned char) rand());
			}

			// time sign_start algorithm
			cycles = rdtsc();
			luov_sign_start(partial_signature, sk);
			sign_start_cyc += rdtsc() - cycles;

			// time sign_finish algorithm
			cycles = rdtsc();
			luov_sign_finish(sm, &smlen, m, (unsigned long long) message_size, partial_signature);
			sign_finish_cyc += rdtsc() - cycles;

			// time verification algorithm
			cycles = rdtsc();
			if (crypto_sign_open(m2, &smlen, sm, smlen, pk) != 0) {
				printf("Verification of signature Failed!\n");
			}
			verify_cyc += rdtsc() - cycles;

			// check if recovered message length is correct
			if (smlen != message_size){
				printf("Wrong message size !\n");
			}
			// check if recovered message is correct
			for(k = 0 ; k<message_size ; k++){
				if(m[k]!=m2[k]){
					printf("Wrong message !\n");
					break;
				}
			}
		}

	}

	printf("\n");

	printf("Key pair generation took %ld cycles.\n", keygen_cyc / NUMBER_OF_KEYPAIRS);
	printf("Signing_start took %ld cycles.\n", (sign_start_cyc/NUMBER_OF_KEYPAIRS)/SIGNATURES_PER_KEYPAIR );
	printf("Signing_finish took %ld cycles.\n", (sign_finish_cyc/NUMBER_OF_KEYPAIRS)/SIGNATURES_PER_KEYPAIR );
	printf("Verifying took %ld cycles.\n\n", (verify_cyc / NUMBER_OF_KEYPAIRS) / SIGNATURES_PER_KEYPAIR );

	free(pk);
	free(sk);
	free(sm);
	free(_partial_signature);

	return 0;
}

