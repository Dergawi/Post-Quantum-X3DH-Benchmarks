# Post-Quantum-X3DH-Benchmarks

## Overview

This library is a benchmark for 3 different post-quantum X3DH alternatives.

It uses the libraries [liboqs](https://github.com/open-quantum-safe/liboqs), [raptor](https://github.com/zhenfeizhang/raptor) and [lwe-frodo](https://github.com/lwe-frodo/lwe-frodo).

All results are in the folder ./results and the source code is in ./src.

## Quickstart

This library was coded on Ubuntu 22.04 LTS :

1. Fisrt, install all dependencies : 

		 sudo apt install astyle cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml valgrind

2. Then go to ./src/libs/liboqs and run `ninja install`.

3. Go to ./ and create a folder ./exe

4. Run `make`.

5. Go to the ./exe folder and here you can run the 5 different benchmarks.
