all:
	gcc -Wall -g -c ./src/lib_Benchmark.c -o ./build/obj/lib_Benchmark.o
	ar rcs ./build/lib/libBenchmark.a ./build/obj/lib_Benchmark.o

test_sanitized:
	clang -Wall -g -fsanitize=address -o "./test/test" ./test/test.c ./src/lib_Benchmark.c
