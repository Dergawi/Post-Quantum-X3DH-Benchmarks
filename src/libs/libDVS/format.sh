#!/bin/sh
cd src/
clang-format -i libDVS.c
cd ../test/
clang-format -i test.c
cd ../include/
clang-format -i header_DVS.h

