#!/bin/sh
cd src/
clang-format -i lib_SplitKEM.c
cd ../test/
clang-format -i test.c
cd ../include/
clang-format -i header_SplitKEM.h

