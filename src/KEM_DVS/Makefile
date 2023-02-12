CC = gcc
CC_DEBUG = clang
DEBUG_FLAG = -g -Wall -fsanitize=address -fsanitize=undefined
SRC_FILES = ./src/
OBJ_FILES = ./obj/
EXE_FILES = ../../exe/
TEST_FILES = ./exe/
LIBS = ../libs/libKEM/build/lib/libKEM.a ../libs/libBenchmark/build/lib/libBenchmark.a ../libs/libDVS/build/lib/libDVS.a -loqs -lm -lsodium -lcrypto
EXEC = KEM_DVS

all: $(EXEC)

KEM_DVS: $(OBJ_FILES)KEM_DVS.o $(OBJ_FILES)libProtocol.o
	$(CC) -o $(EXE_FILES)$@ $^ $(LIBS)

$(OBJ_FILES)KEM_DVS.o: $(SRC_FILES)KEM_DVS.c
	$(CC) -o $@ -c $<

$(OBJ_FILES)libProtocol.o: $(SRC_FILES)libProtocol.c
	$(CC) -o $@ -c $<

sanitized: KEM_DVS_sanitized

KEM_DVS_sanitized: $(SRC_FILES)KEM_DVS.c $(SRC_FILES)libProtocol.c
	$(CC_DEBUG) $(DEBUG_FLAG) -o $(TEST_FILES)$@ $^ $(LIBS)

clean:
	rm -rf $(OBJ_FILES)*.o
