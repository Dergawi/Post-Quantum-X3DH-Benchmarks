all:
	gcc -Wall -g -c ./src/lib_KEM.c -o ./build/obj/lib_KEM.o
	ar rcs ./build/lib/libKEM.a ./build/obj/lib_KEM.o

test_sanitized:
	clang -Wall -g -fsanitize=address -o "./test/test" ./test/test.c ./src/lib_KEM.c -loqs -lcrypto
