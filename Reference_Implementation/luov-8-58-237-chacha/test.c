#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#include "parameters.h"

#include "F16Field.h"
#include "F32Field.h"
#include "F48Field.h"
#include "F64Field.h"
#include "F80Field.h"

#include "LUOV.h"

#include "api.h"

#define NUMBER_OF_KEYPAIRS 2      /* Number of keypairs that is generated during test */
#define SIGNATURES_PER_KEYPAIR 1  /* Number of times each keypair is used to sign a random document, and verify the signature */

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
	unsigned char *sm = malloc(sizeof(unsigned char[message_size + CRYPTO_BYTES]));
	clock_t cl;

	// Print key and signature sizes
	printf("Public Key takes %d B\n", CRYPTO_PUBLICKEYBYTES );
	printf("Secret Key takes %d B\n", CRYPTO_SECRETKEYBYTES );
	printf("Signature takes %d B\n\n", CRYPTO_BYTES );

	printf("Public Key takes %.2f kB\n", CRYPTO_PUBLICKEYBYTES / 1024.0);
	printf("Secret Key takes %.2f kB\n", CRYPTO_SECRETKEYBYTES / 1024.0);
	printf("Signature takes %.2f kB\n\n", CRYPTO_BYTES / 1024.0);

	srand((unsigned int) time(NULL));

	float genTime = 0.0;
	float signTime = 0.0;
	float verifyTime = 0.0;
	uint64_t keygen_cyc = 0;
	uint64_t sign_cyc = 0;
	uint64_t verify_cyc = 0;
	uint64_t cycles = 0;

	for (i = 0; i < NUMBER_OF_KEYPAIRS ; i++) {

		// time key pair generation
		cl = clock();
		cycles = rdtsc();
		crypto_sign_keypair(pk, sk);
		keygen_cyc += rdtsc()-cycles;
		cl = clock() - cl;
		genTime += ((float) cl)/CLOCKS_PER_SEC;

		for (j = 0; j < SIGNATURES_PER_KEYPAIR ; j++) {
			
			// pick a random message to sign
			for (k = 0; k < message_size; k++) {
				m[k] = ((unsigned char) rand());
			}

			// time signing algorithm
			cl = clock();
			cycles = rdtsc();
			crypto_sign(sm, &smlen, m, (unsigned long long) message_size, sk);
			sign_cyc += rdtsc() - cycles;
			cl = clock() - cl;
			signTime += ((float)cl) / CLOCKS_PER_SEC;

			printf("signed message length is %lld B\n", smlen);

			// time verification algorithm
			cl = clock();
			cycles = rdtsc();
			if (crypto_sign_open(m2, &smlen, sm, smlen, pk) != 0) {
				printf("Verification of signature Failed!\n");
			}
			verify_cyc += rdtsc() - cycles;
			cl = clock() - cl;
			verifyTime += ((float)cl) / CLOCKS_PER_SEC;

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
	printf("Key pair generation took %.3f seconds.\n", genTime / NUMBER_OF_KEYPAIRS);
	printf("Signing took %.3f seconds.\n", (signTime/NUMBER_OF_KEYPAIRS)/SIGNATURES_PER_KEYPAIR );
	printf("Verifying took %.3f seconds.\n\n", (verifyTime / NUMBER_OF_KEYPAIRS) / SIGNATURES_PER_KEYPAIR );

	printf("Key pair generation took %ld cycles.\n", keygen_cyc / NUMBER_OF_KEYPAIRS);
	printf("Signing took %ld cycles.\n", (sign_cyc/NUMBER_OF_KEYPAIRS)/SIGNATURES_PER_KEYPAIR );
	printf("Verifying took %ld cycles.\n\n", (verify_cyc / NUMBER_OF_KEYPAIRS) / SIGNATURES_PER_KEYPAIR );

	free(pk);
	free(sk);
	free(sm);

	return 0;
}
