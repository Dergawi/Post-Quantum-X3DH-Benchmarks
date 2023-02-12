all:
	gcc -Wall -g -c ../lwe-frodo/lwekex.c -o ./build/obj/lwekex.o
	gcc -Wall -g -c ./src/lib_SplitKEM.c -o ./build/obj/lib_SplitKEM.o
	ar rcs ./build/lib/libSplitKEM.a ./build/obj/lib_SplitKEM.o ../lwe-frodo/lwekex.o

test_sanitized:
	clang -Wall -g -o "./test/test" ./test/test.c ./src/lib_SplitKEM.c ../lwe-frodo/lwekex.c -lcrypto -lssl -lm
