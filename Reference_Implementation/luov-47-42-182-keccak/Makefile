CC=gcc
CFLAGS=-I/users/cosic/wbeullen/KeccakCodePackage/bin/generic64/ -I/home/ward/KCP/bin/generic64/ # point this and the one below to wherever the keccak code package is located
LFLAGS=-L/users/cosic/wbeullen/KeccakCodePackage/bin/generic64/ -L/home/ward/KCP/bin/generic64/ -lkeccak -lcrypto

IMPLEMENTATION_SOURCE = chacha.c Column.c F7Field.c F79Field.c F47Field.c F61Field.c LUOV.c LinearAlgebra.c buffer.c prng.c rng.c intermediateValues.c
IMPLEMENTATION_HEADERS= chacha.h Column.h F7Field.h F79Field.c F47Field.h F61Field.h LUOV.h LinearAlgebra.h buffer.h prng.h rng.h intermediateValues.h api.h parameters.h 

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
	./fast >> /dev/null && \
	gcc -o fast $(IMPLEMENTATION_SOURCE) test.c $(CFLAGS) $(LFLAGS) -std=c99 -O3 -fprofile-use && \
	rm *.gcda && \
	./fast

.PHONY: clean
clean:
	rm -f test PQCgenKAT_sign  profile profile.txt fast *.req *.rsp >/dev/null
