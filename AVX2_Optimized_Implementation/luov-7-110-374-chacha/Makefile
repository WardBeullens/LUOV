CC=gcc 
CFLAGS=-I/users/cosic/wbeullen/KeccakCodePackage/bin/Haswell/ -I/home/ward/KCP/bin/Haswell/ -I ../../chacha-opt/app/include/ -fno-pie 
LFLAGS=-L/users/cosic/wbeullen/KeccakCodePackage/bin/Haswell/ -L/home/ward/KCP/bin/Haswell/ -L ../../chacha-opt/bin/  -lkeccak -lcrypto -lchacha

IMPLEMENTATION_SOURCE = LUOV.c LinearAlgebra.c keccakrng.c randombytes.c intermediateValues.c sign.c
IMPLEMENTATION_HEADERS= LUOV.h LinearAlgebra.h keccakrng.h randombytes.h intermediateValues.h api.h parameters.h AVX_Operations.h F256Field.h

kat: $(KAT_HEADERS) $(KAT_SOURCES) PQCgenKAT_sign.c
	gcc -o PQCgenKAT_sign $(IMPLEMENTATION_SOURCE) PQCgenKAT_sign.c $(CFLAGS) $(LFLAGS) -mavx2 -DKAT &&\
	./PQCgenKAT_sign > intermediateValues.txt

wall: $(IMPLEMENTATION_SOURCE) $(IMPLEMENTATION_HEADERS) test.c
	gcc -o test $(IMPLEMENTATION_SOURCE) test.c $(CFLAGS) $(LFLAGS) -g -mavx2 -O3 -Wall


test: $(IMPLEMENTATION_SOURCE) $(IMPLEMENTATION_HEADERS) test.c
	gcc -o test $(IMPLEMENTATION_SOURCE) test.c $(CFLAGS) $(LFLAGS) -g -mavx2 -O3

profile: $(IMPLEMENTATION_SOURCE) $(IMPLEMENTATION_HEADERS) test.c
	gcc -o profile $(IMPLEMENTATION_SOURCE) test.c $(CFLAGS) $(LFLAGS) -O3 -pg -g -mavx2 && \
	./profile && \
	gprof ./profile > profile.txt

fast: $(IMPLEMENTATION_SOURCE) $(IMPLEMENTATION_HEADERS) test.c
	gcc -o fast $(IMPLEMENTATION_SOURCE) test.c $(CFLAGS) $(LFLAGS) -O3 -mavx2 && \
	./fast 

fast_precompute: $(IMPLEMENTATION_SOURCE) $(IMPLEMENTATION_HEADERS) test_precompute.c
	gcc -o fast_precompute $(IMPLEMENTATION_SOURCE) test_precompute.c $(CFLAGS) $(LFLAGS) -O3 -mavx2 -fPIC && \
	./fast_precompute

callgrind: $(IMPLEMENTATION_SOURCE) $(IMPLEMENTATION_HEADERS) test.c
	gcc -o fast $(IMPLEMENTATION_SOURCE) test.c $(CFLAGS) $(LFLAGS) -g -std=c99 -O3 -mavx2 &&\
	valgrind --tool=callgrind --dump-instr=yes ./fast

.PHONY: clean
clean:
	rm -f test PQCgenKAT_sign fast_precompute profile profile.txt intermediateValues.txt fast *.req *.rsp >/dev/null
