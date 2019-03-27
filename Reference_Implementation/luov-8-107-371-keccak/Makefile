CC=gcc
CFLAGS=-I../../XKCP/bin/generic64/ 
LFLAGS=-L../../XKCP/bin/generic64/ -lkeccak -lcrypto

IMPLEMENTATION_SOURCE = chacha.c ColumnGenerator.c Column.c F8Field.c F16Field.c F32Field.c F48Field.c F64Field.c F80Field.c LUOV.c LinearAlgebra.c buffer.c prng.c rng.c intermediateValues.c
IMPLEMENTATION_HEADERS= chacha.h ColumnGenerator.h Column.h F8Field.h F16Field.h F32Field.h F48Field.h F64Field.h F80Field.h LUOV.h LinearAlgebra.h buffer.h prng.h rng.h intermediateValues.h api.h parameters.h keccaklib

kat: $(IMPLEMENTATION_HEADERS) $(IMPLEMENTATION_SOURCE) PQCgenKAT_sign.c
	gcc -o PQCgenKAT_sign $(IMPLEMENTATION_SOURCE) PQCgenKAT_sign.c $(CFLAGS) $(LFLAGS) -std=c99 -O3 -DKAT &&\
	./PQCgenKAT_sign > intermediateValues.txt

debug: $(IMPLEMENTATION_SOURCE) $(IMPLEMENTATION_HEADERS) test.c
	gcc -o debug $(IMPLEMENTATION_SOURCE) test.c $(CFLAGS) $(LFLAGS) -std=c99 -g 

test: $(IMPLEMENTATION_SOURCE) $(IMPLEMENTATION_HEADERS) test.c
	gcc -o test $(IMPLEMENTATION_SOURCE) test.c $(CFLAGS) $(LFLAGS) -std=c99 -O3 

keccaklib: 
	(cd ../../XKCP; make generic64/libkeccak.a)

.PHONY: clean
clean:
	rm -f PQCgenKAT_sign test debug test_offline intermediateValues.txt *.req *.rsp >/dev/null
