CC = gcc
CC_DEBUG = clang
DEBUG_FLAG = -g -Wall -fsanitize=address -fsanitize=undefined
SRC_FILES = ./src/
OBJ_FILES = ./obj/
EXE_FILES = ../../exe/
TEST_FILES = ./exe/
LIBS = ../libs/libBenchmark/build/lib/libBenchmark.a -lm -lsodium
EXEC = X3DH_classic

all: $(EXEC)

X3DH_classic: $(OBJ_FILES)X3DH_classic.o $(OBJ_FILES)libProtocol.o
	$(CC) -o $(EXE_FILES)$@ $^ $(LIBS)

$(OBJ_FILES)X3DH_classic.o: $(SRC_FILES)X3DH_classic.c
	$(CC) -o $@ -c $<

$(OBJ_FILES)libProtocol.o: $(SRC_FILES)libProtocol.c
	$(CC) -o $@ -c $<

sanitized: X3DH_classic_sanitized

X3DH_classic_sanitized: $(SRC_FILES)X3DH_classic.c $(SRC_FILES)libProtocol.c
	$(CC_DEBUG) $(DEBUG_FLAG) -o $(TEST_FILES)$@ $^ $(LIBS)

clean:
	rm -rf $(OBJ_FILES)*.o
