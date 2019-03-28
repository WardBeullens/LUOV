CC=gcc
CFLAGS=-I../../XKCP/bin/Haswell/ -I../../chacha-opt/app/include/
LFLAGS=-L../../XKCP/bin/Haswell/ -L../../chacha-opt/bin/ -lkeccak -lcrypto -lchacha

IMPLEMENTATION_SOURCE = LUOV.c LinearAlgebra.c keccakrng.c randombytes.c intermediateValues.c sign.c
IMPLEMENTATION_HEADERS= LUOV.h LinearAlgebra.h keccakrng.h randombytes.h intermediateValues.h api.h parameters.h AVX_Operations.h F256Field.h keccak chacha 

kat: $(IMPLEMENTATION_HEADERS) $(IMPLEMENTATION_SOURCES) PQCgenKAT_sign.c
	gcc -o PQCgenKAT_sign $(IMPLEMENTATION_SOURCE) PQCgenKAT_sign.c $(CFLAGS) $(LFLAGS) -mavx2 -DKAT &&\
	./PQCgenKAT_sign > intermediateValues.txt

test: $(IMPLEMENTATION_SOURCE) $(IMPLEMENTATION_HEADERS) test.c
	gcc -o test $(IMPLEMENTATION_SOURCE) test.c $(CFLAGS) $(LFLAGS) -O3 -mavx2

test_precompute: $(IMPLEMENTATION_SOURCE) $(IMPLEMENTATION_HEADERS) test_precompute.c
	gcc -o test_precompute $(IMPLEMENTATION_SOURCE) test_precompute.c $(CFLAGS) $(LFLAGS) -O3 -mavx2

keccak:
	(cd ../../XKCP; make Haswell/libkeccak.a)

chacha:
	(cd ../../chacha-opt; ./configure; make lib; cd bin; cp chacha.lib libchacha.a)

.PHONY: clean
clean:
	rm -f test PQCgenKAT_sign intermediateValues.txt test_precompute *.req *.rsp >/dev/null
