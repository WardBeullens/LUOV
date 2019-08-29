#ifndef RNG_H
#define RNG_H

#include <stdlib.h>
#include <stdalign.h>
#include <libkeccak.a.headers/KeccakHash.h>
#include <libkeccak.a.headers/KeccakP-1600-SnP.h>
#include <libkeccak.a.headers/KeccakP-1600-times8-SnP.h>
#include <libkeccak.a.headers/KeccakP-1600-times4-SnP.h>
#include <libkeccak.a.headers/KeccakP-1600-times2-SnP.h>
#include "F256Field.h"

#define Sponge Keccak_HashInstance

#define squeezeBytes(S,D,L) Keccak_HashSqueeze (S,D,L * 8)

void initializeAndAbsorb(Sponge *sponge, const unsigned char * seed, int len);
void squeezeVector(Sponge *sponge, FELT *vector , int length);
void squeezeuint64_t(Sponge *sponge, int bytes , uint64_t * a);
void calculateQ1(const unsigned char *seed, bitcontainer *buffer);
void squeezeCols(Sponge *sponge, bitcontainer *arr, int size);

#endif