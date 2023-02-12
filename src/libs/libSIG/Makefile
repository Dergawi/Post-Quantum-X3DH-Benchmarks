all:
	gcc -Wall -g -c ./src/lib_SIG.c -o ./build/obj/lib_SIG.o
	ar rcs ./build/lib/libSIG.a ./build/obj/lib_SIG.o

test_sanitized:
	clang -Wall -g -fsanitize=address -o "./test/test" ./test/test.c ./src/lib_SIG.c -loqs -lcrypto
