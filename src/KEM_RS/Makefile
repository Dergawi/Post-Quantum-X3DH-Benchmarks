CC = gcc
CC_DEBUG = clang
DEBUG_FLAG = -g -Wall -fsanitize=address -fsanitize=undefined
SRC_FILES = ./src/
OBJ_FILES = ./obj/
EXE_FILES = ../../exe/
TEST_FILES = ./exe/
LIBS = ../libs/libKEM/build/lib/libKEM.a ../libs/libBenchmark/build/lib/libBenchmark.a ../libs/libRS/build/lib/libRS.a -loqs -lm -lsodium -lcrypto
EXEC = KEM_RS

all: $(EXEC)

KEM_RS: $(OBJ_FILES)KEM_RS.o $(OBJ_FILES)libProtocol.o
	$(CC) -o $(EXE_FILES)$@ $^ $(LIBS)

$(OBJ_FILES)KEM_RS.o: $(SRC_FILES)KEM_RS.c
	$(CC) -o $@ -c $<

$(OBJ_FILES)libProtocol.o: $(SRC_FILES)libProtocol.c
	$(CC) -o $@ -c $<

sanitized: KEM_RS_sanitized

KEM_RS_sanitized: $(SRC_FILES)KEM_RS.c $(SRC_FILES)libProtocol.c
	$(CC_DEBUG) $(DEBUG_FLAG) -o $(TEST_FILES)$@ $^ $(LIBS)

clean:
	rm -rf $(OBJ_FILES)*.o
