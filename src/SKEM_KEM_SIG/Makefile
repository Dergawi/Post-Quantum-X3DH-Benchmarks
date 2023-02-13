CC = gcc
CC_DEBUG = clang
DEBUG_FLAG = -g -Wall -fsanitize=address -fsanitize=undefined
SRC_FILES = ./src/
OBJ_FILES = ./obj/
EXE_FILES = ../../exe/
TEST_FILES = ./exe/
LIBS = ../libs/libBenchmark/build/lib/libBenchmark.a ../libs/libKEM/build/lib/libKEM.a ../libs/libSplitKEM/build/lib/libSplitKEM.a ../libs/libSIG/build/lib/libSIG.a -loqs -lm -lsodium -lcrypto
EXEC = SKEM_KEM_SIG

all: $(EXEC)

SKEM_KEM_SIG: $(OBJ_FILES)SKEM_KEM_SIG.o $(OBJ_FILES)libProtocol.o
	$(CC) -o $(EXE_FILES)$@ $^ $(LIBS)

$(OBJ_FILES)SKEM_KEM_SIG.o: $(SRC_FILES)SKEM_KEM_SIG.c
	$(CC) -o $@ -c $<

$(OBJ_FILES)libProtocol.o: $(SRC_FILES)libProtocol.c
	$(CC) -o $@ -c $<

sanitized: SKEM_KEM_SIG_sanitized

SKEM_KEM_SIG_sanitized: $(SRC_FILES)SKEM_KEM_SIG.c $(SRC_FILES)libProtocol.c
	$(CC_DEBUG) $(DEBUG_FLAG) -o $(TEST_FILES)$@ $^ $(LIBS)

clean:
	rm -rf $(OBJ_FILES)*.o
