CC=gcc
CFLAGS=-I/users/cosic/wbeullen/KeccakCodePackage/bin/generic64/ -I/home/ward/Desktop/KeccakCodePackage/bin/generic32/ # point this and the one below to wherever the keccak code package is located
LFLAGS=-L/users/cosic/wbeullen/KeccakCodePackage/bin/generic64/ -L/home/ward/Desktop/KeccakCodePackage/bin/generic32/ -lkeccak -lcrypto

IMPLEMENTATION_SOURCE = Bitcontainer.c F8Field.c F16Field.c F32Field.c F48Field.c F64Field.c F80Field.c LUOV.c LinearAlgebra.c buffer.c keccakrng.c rng.c intermediateValues.c sign.c
IMPLEMENTATION_HEADERS= Bitcontainer.h F8Field.h F16Field.h F32Field.h F48Field.h F64Field.h F80Field.h LUOV.h LinearAlgebra.h buffer.h keccakrng.h rng.h intermediateValues.h api.h parameters.h 

kat: $(KAT_HEADERS) $(KAT_SOURCES) PQCgenKAT_sign.c
	gcc -o PQCgenKAT_sign $(IMPLEMENTATION_SOURCE) PQCgenKAT_sign.c $(CFLAGS) $(LFLAGS) -std=c99 -DKAT &&\
	./PQCgenKAT_sign > intermediateValues.txt

test: $(IMPLEMENTATION_SOURCE) $(IMPLEMENTATION_HEADERS) test.c
	gcc -o test $(IMPLEMENTATION_SOURCE) test.c $(CFLAGS) $(LFLAGS) -std=c99 -g

profile: $(IMPLEMENTATION_SOURCE) $(IMPLEMENTATION_HEADERS) test.c
	gcc -o profile $(IMPLEMENTATION_SOURCE) test.c $(CFLAGS) $(LFLAGS) -std=c99 -O3 -pg -g && \
	./profile && \
	gprof ./profile > profile.txt

fast: $(IMPLEMENTATION_SOURCE) $(IMPLEMENTATION_HEADERS) test.c
	gcc -o fast $(IMPLEMENTATION_SOURCE) test.c $(CFLAGS) $(LFLAGS) -std=c99 -O3 -fprofile-generate && \
	./fast && \
	gcc -o fast $(IMPLEMENTATION_SOURCE) test.c $(CFLAGS) $(LFLAGS) -std=c99 -O3 -fprofile-use && \
	rm *.gcda && \
	./fast

.PHONY: clean
clean:
	rm -f test PQCgenKAT_sign  profile profile.txt fast *.req *.rsp >/dev/null
