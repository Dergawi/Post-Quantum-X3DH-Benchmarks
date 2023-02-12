all:
	gcc -Wall -g -c ../raptor/rng/crypto_hash_sha512.c -o ./build/obj/crypto_hash_sha512.o
	gcc -Wall -g -c ../raptor/rng/fastrandombytes.c -o ./build/obj/fastrandombytes.o
	gcc -Wall -g -c ../raptor/rng/rng.c -o ./build/obj/rng.o
	gcc -Wall -g -c ../raptor/rng/shred.c -o ./build/obj/shred.o
	gcc -Wall -g -c ../raptor/falcon/crypto_stream.c -o ./build/obj/crypto_stream.o
	gcc -Wall -g -c ../raptor/falcon/falcon-enc.c -o ./build/obj/falcon-enc.o
	gcc -Wall -g -c ../raptor/falcon/falcon-fft.c -o ./build/obj/falcon-fft.o
	gcc -Wall -g -c ../raptor/falcon/falcon-keygen.c -o ./build/obj/falcon-keygen.o
	gcc -Wall -g -c ../raptor/falcon/falcon-sign.c -o ./build/obj/falcon-sign.o
	gcc -Wall -g -c ../raptor/falcon/falcon-vrfy.c -o ./build/obj/falcon-vrfy.o
	gcc -Wall -g -c ../raptor/falcon/frng.c -o ./build/obj/frng.o
	gcc -Wall -g -c ../raptor/falcon/nist.c -o ./build/obj/nist.o
	gcc -Wall -g -c ../raptor/falcon/shake.c -o ./build/obj/shake.o
	gcc -Wall -g -c ../raptor/raptor.c -o ./build/obj/raptor.o
	gcc -Wall -g -c ../raptor/poly.c -o ./build/obj/poly.o
	gcc -Wall -g -c ../raptor/print.c -o ./build/obj/print.o
	gcc -Wall -g -c ./src/lib_RS.c -o ./build/obj/lib_RS.o
	ar rcs ./build/lib/libRS.a ./build/obj/crypto_hash_sha512.o ./build/obj/fastrandombytes.o ./build/obj/rng.o ./build/obj/shred.o ./build/obj/crypto_stream.o ./build/obj/falcon-enc.o ./build/obj/falcon-fft.o ./build/obj/falcon-keygen.o ./build/obj/falcon-sign.o ./build/obj/falcon-vrfy.o ./build/obj/frng.o ./build/obj/nist.o ./build/obj/shake.o ./build/obj/raptor.o ./build/obj/poly.o ./build/obj/print.o ./build/obj/lib_RS.o

test_sanitized:
	clang -Wall -g -fsanitize=address -o "./test/test" ./test/test.c ../raptor/rng/crypto_hash_sha512.c ../raptor/rng/fastrandombytes.c ../raptor/rng/rng.c ../raptor/rng/shred.c  ../raptor/falcon/crypto_stream.c ../raptor/falcon/falcon-enc.c ../raptor/falcon/falcon-fft.c ../raptor/falcon/falcon-keygen.c ../raptor/falcon/falcon-sign.c ../raptor/falcon/falcon-vrfy.c ../raptor/falcon/frng.c ../raptor/falcon/nist.c ../raptor/falcon/shake.c  ../raptor/raptor.c ../raptor/linkable_raptor.o ../raptor/poly.c ../raptor/print.c ./src/lib_RS.c -lcrypto
