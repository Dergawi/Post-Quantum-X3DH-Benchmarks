# Post-Quantum-X3DH-Benchmarks

## Overview

This library is a benchmark for 3 different post-quantum X3DH alternatives.

It uses the libraries [liboqs](https://github.com/open-quantum-safe/liboqs), [raptor](https://github.com/zhenfeizhang/raptor) and [lwe-frodo](https://github.com/lwe-frodo/lwe-frodo).

## Quickstart

This library was coded on Ubuntu 22.04 LTS :

1. Fisrt, reinstall all dependencies : 

		 sudo apt install astyle cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml valgrind

2. Then go to the liboqs folder and run `ninja install`.
