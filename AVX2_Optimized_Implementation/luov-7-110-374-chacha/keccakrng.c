#include "keccakrng.h"
#include "immintrin.h"

/* 
	Initializes a Sponge object, absorbs a seed and finalizes the absorbing phase

	 sponge  : The sponge object
	 seed    : The seed to absorb
	 len     : The length of the seed
*/
void initializeAndAbsorb(Sponge *sponge ,const unsigned char * seed , int len ) {
	Keccak_HashInitialize_SHAKE(sponge);
	Keccak_HashUpdate(sponge, seed, len*8 );
	Keccak_HashFinal(sponge, 0 );
}

/* 
	Squeezes a uint64_t from the sponge object

	sponge : The sponge object
	bytes  : The number of bytes to squeeze from the sponge (should be between 1 and 8)
*/
void squeezeuint64_t(Sponge *sponge, int bytes, uint64_t *a){
	Keccak_HashSqueeze(sponge,(unsigned char *) a, bytes*8);
}

/* 
	Squeeze a list of Field elements from the sponge

	sponge : The sponge object
	vector : receives the list of field elements
	length : The length of the list of elements
*/
void squeezeVector(Sponge *sponge, FELT *vector, int length) {
	// Squeeze the appropriate number of bytes from the sponge
	Keccak_HashSqueeze(sponge ,vector , length*8);
}

#ifdef PRNG_KECCAK

#if OIL_VARS <= 64
void calculateQ1(const unsigned char *seed, bitcontainer *Q1){
	int i,j;

	alignas (KeccakP1600times4_statesAlignment) unsigned char state[KeccakP1600times4_statesSizeInBytes] = {0};
	for(i=0; i<4 ; i++){
		//Manual SHAKE absorbtion
		KeccakP1600times4_AddBytes(state, i, seed, 0, 32);
		KeccakP1600times4_AddByte(state, i, (unsigned char) i, 32);
		KeccakP1600times4_AddByte(state, i, 0x1F, 33);
		KeccakP1600times4_AddByte(state, i, 0x80, 167);
	}

	unsigned char blocks[4][168];
	int used = 84;
	int cols = 0;
	bitcontainer C;

	while (cols < Q1_COLS){
		if(used == 84){
			KeccakP1600times4_PermuteAll_24rounds(state);
			for (i = 0; i < 4; ++i)
			{
				KeccakP1600times4_ExtractBytes(state, i, blocks[i], 0, 168);
			}
			used = 0;
		}
		for(i=0; i<4; i++){
			uint16_t *a = ((uint16_t *) &C);
			a[i] = *((uint16_t *) &blocks[i][2*used]);    
		}
		Q1[cols] = C;
		used ++;
		cols ++;
	}
}
#elif OIL_VARS <= 96

void calculateQ1(const unsigned char *seed, bitcontainer *Q1){
	int i,j;

	alignas (KeccakP1600times4_statesAlignment) unsigned char state4[KeccakP1600times4_statesSizeInBytes] = {0};
	alignas (KeccakP1600times2_statesAlignment) unsigned char state2[KeccakP1600times2_statesSizeInBytes] = {0};

	for(i=0; i<4 ; i++){
		//Manual SHAKE absorbtion
		KeccakP1600times4_AddBytes(state4, i, seed, 0, 32);
		KeccakP1600times4_AddByte(state4, i, (unsigned char) i, 32);
		KeccakP1600times4_AddByte(state4, i, 0x1F, 33);
		KeccakP1600times4_AddByte(state4, i, 0x80, 167);
	}
	for(i=0; i<2 ; i++){
		//Manual SHAKE absorbtion
		KeccakP1600times2_AddBytes(state2, i, seed, 0, 32);
		KeccakP1600times2_AddByte(state2, i, (unsigned char) 4+i, 32);
		KeccakP1600times2_AddByte(state2, i, 0x1F, 33);
		KeccakP1600times2_AddByte(state2, i, 0x80, 167);
	}

	unsigned char blocks[6][168];
	int used = 84;
	int cols = 0;
	bitcontainer C;

	while (cols < Q1_COLS){
		if(used == 84){
			KeccakP1600times4_PermuteAll_24rounds(state4);
			KeccakP1600times2_PermuteAll_24rounds(state2);
			for (i = 0; i < 4; ++i)
			{
				KeccakP1600times4_ExtractBytes(state4, i, blocks[i], 0, 168);
			}
			for (i = 0; i < 2; ++i)
			{
				KeccakP1600times2_ExtractBytes(state2, i, blocks[i+4], 0, 168);
			}
			used = 0;
		}
		for(i=0; i<6; i++){
			uint16_t *a = ((uint16_t *) &C);
			a[i] = *((uint16_t *) &blocks[i][2*used]);    
		}
		Q1[cols] = C;
		used ++;
		cols ++;
	}
}

#elif OIL_VARS <= 128

#define NUMBER_OF_STATES ((OIL_VARS+15)/16)

void calculateQ1(const unsigned char *seed, bitcontainer *Q1){
	int i,j;

	alignas (KeccakP1600times8_statesAlignment) unsigned char state8[KeccakP1600times8_statesSizeInBytes] = {0};

	for(i=0; i<NUMBER_OF_STATES ; i++){
		//Manual SHAKE absorbtion
		KeccakP1600times8_AddBytes(state8, i, seed, 0, 32);
		KeccakP1600times8_AddByte(state8, i, (unsigned char) i, 32);
		KeccakP1600times8_AddByte(state8, i, 0x1F, 33);
		KeccakP1600times8_AddByte(state8, i, 0x80, 167);
	}

	unsigned char blocks[8][168];
	int used = 84;
	int cols = 0;
	bitcontainer C;

	while (cols < Q1_COLS){
		if(used == 84){
			KeccakP1600times8_PermuteAll_24rounds(state8);
			for (i = 0; i < NUMBER_OF_STATES; ++i)
			{
				KeccakP1600times8_ExtractBytes(state8, i, blocks[i], 0, 168);
			}
			used = 0;
		}

		for(i=0; i<NUMBER_OF_STATES; i++){
			uint16_t *a = ((uint16_t *) &C);
			a[i] = *((uint16_t *) &blocks[i][2*used]);    
		}
		Q1[cols] = C;
		used ++;
		cols ++;
	}
}

#endif
#endif

#ifdef PRNG_CHACHA

#include "chacha.h"
#define NUMBER_OF_STATES ((OIL_VARS+15)/16)

#if OIL_VARS <=64

void calculateQ1(const unsigned char *seed, bitcontainer *Q1){
	int i,j;

	unsigned char blocks[NUMBER_OF_STATES][Q1_COLS*2];
	unsigned char dummy[Q1_COLS*2] = {0};
	int cols = 0;
	bitcontainer C;

	unsigned char nonce[8] = {0};

	chacha_key key;
	memcpy(key.b,seed,32);

	chacha_iv iv;
	memset(iv.b,0,8);

	for(i = 0; i<NUMBER_OF_STATES ; i++){
		nonce[0] = i;
		iv.b[0] = (unsigned char) i;
		chacha(&key, &iv, dummy, blocks[i], Q1_COLS*2, 8);
	}

	while (cols + 16 <= Q1_COLS){
		__m256i x1,x2,x3,x4;
		__m256i y1,y2,y3,y4;

		x1 = _mm256_loadu_si256((__m256i*) (blocks[0]+2*cols));
		x2 = _mm256_loadu_si256((__m256i*) (blocks[1]+2*cols));
		x3 = _mm256_loadu_si256((__m256i*) (blocks[2]+2*cols));
		x4 = _mm256_loadu_si256((__m256i*) (blocks[3]+2*cols));

		y1 = _mm256_unpacklo_epi16(x1,x2);
		y2 = _mm256_unpackhi_epi16(x1,x2);
		y3 = _mm256_unpacklo_epi16(x3,x4);
		y4 = _mm256_unpackhi_epi16(x3,x4);

		x1 = _mm256_unpacklo_epi32(y1,y3);
		x2 = _mm256_unpackhi_epi32(y1,y3);
		x3 = _mm256_unpacklo_epi32(y2,y4);
		x4 = _mm256_unpackhi_epi32(y2,y4);

		Q1[cols   ] = _mm256_extract_epi64(x1,0);
		Q1[cols+ 1] = _mm256_extract_epi64(x1,1);
		Q1[cols+ 2] = _mm256_extract_epi64(x2,0);
		Q1[cols+ 3] = _mm256_extract_epi64(x2,1);
		Q1[cols+ 4] = _mm256_extract_epi64(x3,0);
		Q1[cols+ 5] = _mm256_extract_epi64(x3,1);
		Q1[cols+ 6] = _mm256_extract_epi64(x4,0);
		Q1[cols+ 7] = _mm256_extract_epi64(x4,1);

		Q1[cols+ 8] = _mm256_extract_epi64(x1,2);
		Q1[cols+ 9] = _mm256_extract_epi64(x1,3);
		Q1[cols+10] = _mm256_extract_epi64(x2,2);
		Q1[cols+11] = _mm256_extract_epi64(x2,3);
		Q1[cols+12] = _mm256_extract_epi64(x3,2);
		Q1[cols+13] = _mm256_extract_epi64(x3,3);
		Q1[cols+14] = _mm256_extract_epi64(x4,2);
		Q1[cols+15] = _mm256_extract_epi64(x4,3);

		cols += 16;
	}

	while (cols < Q1_COLS){
		for(i=0; i<NUMBER_OF_STATES; i++){
			uint16_t *a = ((uint16_t *) &C);
			a[i] = *((uint16_t *) &blocks[i][2*cols]);    
		}
		Q1[cols] = C;
		cols ++;
	}
}

#elif OIL_VARS <= 128 

void calculateQ1(const unsigned char *seed, bitcontainer *Q1){
	int i,j;

	unsigned char blocks[NUMBER_OF_STATES][Q1_COLS*2];
	unsigned char dummy[Q1_COLS*2] = {0};
	int cols = 0;
	bitcontainer C;

	unsigned char nonce[8] = {0};

	chacha_key key;
	memcpy(key.b,seed,32);

	chacha_iv iv;
	memset(iv.b,0,8);

	for(i = 0; i<NUMBER_OF_STATES ; i++){
		nonce[0] = i;
		iv.b[0] = (unsigned char) i;
		chacha(&key, &iv, dummy, blocks[i], Q1_COLS*2, 8);
	}

	while (cols + 16 <= Q1_COLS){
		__m256i x1,x2,x3,x4;
		__m256i y1,y2,y3,y4;

		x1 = _mm256_loadu_si256((__m256i*) (blocks[0]+2*cols));
		x2 = _mm256_loadu_si256((__m256i*) (blocks[1]+2*cols));
		x3 = _mm256_loadu_si256((__m256i*) (blocks[2]+2*cols));
		x4 = _mm256_loadu_si256((__m256i*) (blocks[3]+2*cols));

		y1 = _mm256_unpacklo_epi16(x1,x2);
		y2 = _mm256_unpackhi_epi16(x1,x2);
		y3 = _mm256_unpacklo_epi16(x3,x4);
		y4 = _mm256_unpackhi_epi16(x3,x4);

		x1 = _mm256_unpacklo_epi32(y1,y3);
		x2 = _mm256_unpackhi_epi32(y1,y3);
		x3 = _mm256_unpacklo_epi32(y2,y4);
		x4 = _mm256_unpackhi_epi32(y2,y4);

		Q1[cols   ] = _mm_insert_epi64(Q1[cols   ],_mm256_extract_epi64(x1,0),0);
		Q1[cols+ 1] = _mm_insert_epi64(Q1[cols+ 1],_mm256_extract_epi64(x1,1),0);
		Q1[cols+ 2] = _mm_insert_epi64(Q1[cols+ 2],_mm256_extract_epi64(x2,0),0);
		Q1[cols+ 3] = _mm_insert_epi64(Q1[cols+ 3],_mm256_extract_epi64(x2,1),0);
		Q1[cols+ 4] = _mm_insert_epi64(Q1[cols+ 4],_mm256_extract_epi64(x3,0),0);
		Q1[cols+ 5] = _mm_insert_epi64(Q1[cols+ 5],_mm256_extract_epi64(x3,1),0);
		Q1[cols+ 6] = _mm_insert_epi64(Q1[cols+ 6],_mm256_extract_epi64(x4,0),0);
		Q1[cols+ 7] = _mm_insert_epi64(Q1[cols+ 7],_mm256_extract_epi64(x4,1),0);

		Q1[cols+ 8] = _mm_insert_epi64(Q1[cols+ 8],_mm256_extract_epi64(x1,2),0);
		Q1[cols+ 9] = _mm_insert_epi64(Q1[cols+ 9],_mm256_extract_epi64(x1,3),0);
		Q1[cols+10] = _mm_insert_epi64(Q1[cols+10],_mm256_extract_epi64(x2,2),0);
		Q1[cols+11] = _mm_insert_epi64(Q1[cols+11],_mm256_extract_epi64(x2,3),0);
		Q1[cols+12] = _mm_insert_epi64(Q1[cols+12],_mm256_extract_epi64(x3,2),0);
		Q1[cols+13] = _mm_insert_epi64(Q1[cols+13],_mm256_extract_epi64(x3,3),0);
		Q1[cols+14] = _mm_insert_epi64(Q1[cols+14],_mm256_extract_epi64(x4,2),0);
		Q1[cols+15] = _mm_insert_epi64(Q1[cols+15],_mm256_extract_epi64(x4,3),0);

		x1 = _mm256_loadu_si256((__m256i*) (blocks[4]+2*cols));
		x2 = _mm256_loadu_si256((__m256i*) (blocks[5]+2*cols));
		#if OIL_VARS == 83
			x3 = _mm256_setzero_si256();
		#elif OIL_VARS == 110
			x3 = _mm256_loadu_si256((__m256i*) (blocks[6]+2*cols));
		#else
			Parameters not supported
		#endif
		x4 = _mm256_setzero_si256();

		y1 = _mm256_unpacklo_epi16(x1,x2);
		y2 = _mm256_unpackhi_epi16(x1,x2);
		y3 = _mm256_unpacklo_epi16(x3,x4);
		y4 = _mm256_unpackhi_epi16(x3,x4);

		x1 = _mm256_unpacklo_epi32(y1,y3);
		x2 = _mm256_unpackhi_epi32(y1,y3);
		x3 = _mm256_unpacklo_epi32(y2,y4);
		x4 = _mm256_unpackhi_epi32(y2,y4);

		Q1[cols   ] = _mm_insert_epi64(Q1[cols   ],_mm256_extract_epi64(x1,0),1);
		Q1[cols+ 1] = _mm_insert_epi64(Q1[cols+ 1],_mm256_extract_epi64(x1,1),1);
		Q1[cols+ 2] = _mm_insert_epi64(Q1[cols+ 2],_mm256_extract_epi64(x2,0),1);
		Q1[cols+ 3] = _mm_insert_epi64(Q1[cols+ 3],_mm256_extract_epi64(x2,1),1);
		Q1[cols+ 4] = _mm_insert_epi64(Q1[cols+ 4],_mm256_extract_epi64(x3,0),1);
		Q1[cols+ 5] = _mm_insert_epi64(Q1[cols+ 5],_mm256_extract_epi64(x3,1),1);
		Q1[cols+ 6] = _mm_insert_epi64(Q1[cols+ 6],_mm256_extract_epi64(x4,0),1);
		Q1[cols+ 7] = _mm_insert_epi64(Q1[cols+ 7],_mm256_extract_epi64(x4,1),1);

		Q1[cols+ 8] = _mm_insert_epi64(Q1[cols+ 8],_mm256_extract_epi64(x1,2),1);
		Q1[cols+ 9] = _mm_insert_epi64(Q1[cols+ 9],_mm256_extract_epi64(x1,3),1);
		Q1[cols+10] = _mm_insert_epi64(Q1[cols+10],_mm256_extract_epi64(x2,2),1);
		Q1[cols+11] = _mm_insert_epi64(Q1[cols+11],_mm256_extract_epi64(x2,3),1);
		Q1[cols+12] = _mm_insert_epi64(Q1[cols+12],_mm256_extract_epi64(x3,2),1);
		Q1[cols+13] = _mm_insert_epi64(Q1[cols+13],_mm256_extract_epi64(x3,3),1);
		Q1[cols+14] = _mm_insert_epi64(Q1[cols+14],_mm256_extract_epi64(x4,2),1);
		Q1[cols+15] = _mm_insert_epi64(Q1[cols+15],_mm256_extract_epi64(x4,3),1);

		cols += 16;
	}

	while (cols < Q1_COLS){
		for(i=0; i<NUMBER_OF_STATES; i++){
			uint16_t *a = ((uint16_t *) &C);
			a[i] = *((uint16_t *) &blocks[i][2*cols]);    
		}
		Q1[cols] = C;
		cols ++;
	}
}

#endif

#endif

#if OIL_VARS <= 64

/*
	Generates an array of bitcontainers

	sponge : pointer to a Sponge object
	arr    : the array that will receive the generated bitcontainers
	size   : the number of bitcontainers that is generated
*/
void squeezeCols(Sponge *sponge, bitcontainer *arr, int size) {
	Keccak_HashSqueeze(sponge,(void *)arr, size*64);
}

#elif (OIL_VARS > 64)

void squeezeCols(Sponge *sponge, bitcontainer *arr, int size) {
	uint8_t *buffer = malloc(COL_PRG_BYTES*size);
	Keccak_HashSqueeze(sponge,(void *) buffer,8*COL_PRG_BYTES*size);
	int i;
	for(i=0 ; i<size ; i++){
		arr[i] = _mm_loadu_si128((__m128i *)(buffer + i*COL_PRG_BYTES));
	}
	free(buffer);
}

#endif

static inline uint64_t rotl(const uint64_t x, int k) {
	return (x << k) | (x >> (64 - k));
}
