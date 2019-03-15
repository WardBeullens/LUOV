#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#include "parameters.h"

#include "F256Field.h"

#include "LUOV.h"

#include "api.h"

#define NUMBER_OF_KEYPAIRS 100   /* Number of keypairs that is generated during test */
#define SIGNATURES_PER_KEYPAIR 1 /* Number of times each keypair is used to sign a random document, and verify the signature */
#define VERIFICATIONS_PER_SIGNATURE 1

void* aligned_alloc(size_t, size_t);

/*
	Tests the execution of the keypair generation, signature generation and signature verification algorithms and prints timing results
*/
int main(void)
{
	int i, j, k;
	int message_size = 50;
	unsigned long long smlen;
	unsigned long long mlen;
	unsigned char m[message_size];
	unsigned char m2[message_size];
	unsigned char *pk = aligned_alloc(32,sizeof(unsigned char[PUBLIC_KEY_BYTES]));
	unsigned char *sk = aligned_alloc(32,sizeof(unsigned char[SECRET_KEY_BYTES]));
	unsigned char *big_pk = aligned_alloc(32,sizeof(unsigned char[BIG_PUBLIC_KEY_BYTES]));
	unsigned char *big_sk = aligned_alloc(32,sizeof(unsigned char[BIG_SECRET_KEY_BYTES]));
	unsigned char *sm = aligned_alloc(32,sizeof(unsigned char[message_size+CRYPTO_BYTES]));
	uint64_t cl;

	int chacha_startup(void);

	// Print key and signature sizes
	printf("Public Key takes %d B\n", PUBLIC_KEY_BYTES );
	printf("Secret Key takes %d B\n", SECRET_KEY_BYTES );
	printf("Big public Key takes %d B\n", BIG_PUBLIC_KEY_BYTES );
	printf("Big secret Key takes %d B\n", BIG_SECRET_KEY_BYTES );
	printf("Signature takes %d B\n\n", CRYPTO_BYTES );

	srand((unsigned int) time(NULL));

	uint64_t genTime = 0;
	uint64_t preSkTime = 0;
	uint64_t prePkTime = 0;
	uint64_t signTime = 0;
	uint64_t verifyTime = 0;

	for (i = 0; i < NUMBER_OF_KEYPAIRS ; i++) {

		// time key pair generation
		cl = rdtsc();
		luov_generateKeyPair(pk, sk);
		genTime += rdtsc() - cl;

		for (j = 0; j < SIGNATURES_PER_KEYPAIR ; j++) {
			// pick a random message to sign
			for (k = 0; k < message_size; k++) {
				m[k] = ((unsigned char) rand());
			}

			// time precompute sk algorithm
			cl = rdtsc();
			luov_precompute_sign(big_sk, sk);
			preSkTime += rdtsc() - cl;

			// time precompute sk algorithm
			cl = rdtsc();
			luov_precompute_verify(big_pk , pk);
			prePkTime += rdtsc() - cl;
			
			// time signing algorithm
			cl = rdtsc();
			luov_sign_fast(sm,&smlen,m,(unsigned long long) message_size,big_sk);
			signTime += rdtsc() - cl;
			
			// time verification algorithm
			int verifs;
			cl = rdtsc();
			for(verifs = 0 ; verifs < VERIFICATIONS_PER_SIGNATURE ; verifs++){
				if (luov_verify_fast(big_pk , sm, smlen, m2, &mlen) != 0) {
					printf("Verification of signature Failed!\n");
				}
			}
			uint64_t a = rdtsc() - cl;
			verifyTime += a;

			// check if recovered message length is correct
			if (mlen != message_size){
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

	printf("Key pair generation took %llu cycles.\n",(long long unsigned) genTime / NUMBER_OF_KEYPAIRS);
	printf("Precomputation on sk took %llu cycles.\n", (long long unsigned) (preSkTime/NUMBER_OF_KEYPAIRS)/SIGNATURES_PER_KEYPAIR );
	printf("Precomputation on pk took %llu cycles.\n", (long long unsigned) (prePkTime/NUMBER_OF_KEYPAIRS)/SIGNATURES_PER_KEYPAIR );
	printf("Signing took %llu cycles.\n", (long long unsigned) (signTime/NUMBER_OF_KEYPAIRS)/SIGNATURES_PER_KEYPAIR );
	printf("Verifying took %llu cycles.\n\n", (long long unsigned) (verifyTime / NUMBER_OF_KEYPAIRS) / SIGNATURES_PER_KEYPAIR / VERIFICATIONS_PER_SIGNATURE );

	free(pk);
	free(sk);
	free(sm);

	return 0;
}
