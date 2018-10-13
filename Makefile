CC = gcc
CXX = g++
UNAME = $(shell uname)
CFLAGS = $(shell pkg-config --libs sqlite3) $(shell pkg-config --cflags sqlite3) -fPIC
ARCH = $(shell getconf LONG_BIT)
DUMPMACHINE = $(shell $(CC) -dumpmachine -m$(ARCH))
CXXFLAGS = $(CFLAGS) -lsqlite-crypto-vfs -Llib/$(DUMPMACHINE)
SRC_ROOT = src
SQLITE_CRYPTO_VFS_SOURCE = $(SRC_ROOT)/aes.c $(SRC_ROOT)/sqlite-crypto-vfs.c

ifeq ($(UNAME), Linux)
LIB_PREFIX = lib
LIB_SUFFIX = .so
else ifeq ($(UNAME), Darwin)
LIB_PREFIX = lib
LIB_SUFFIX = .dylib
endif

default: build

clean:
	rm -Rf lib
	rm -Rf bin

build: sqlite-crypto-vfs

mkdir-lib:
	mkdir -p lib/$(DUMPMACHINE)

sqlite-crypto-vfs-arch64: mkdir-lib
	$(CC) $(CFLAGS) -shared -m64 -o lib/$(DUMPMACHINE)/$(LIB_PREFIX)sqlite-crypto-vfs$(LIB_SUFFIX) $(SQLITE_CRYPTO_VFS_SOURCE)

sqlite-crypto-vfs-arch32: mkdir-lib
	$(CC) $(CFLAGS) -shared -m32 -o lib/$(DUMPMACHINE)/$(LIB_PREFIX)sqlite-crypto-vfs$(LIB_SUFFIX) $(SQLITE_CRYPTO_VFS_SOURCE)

sqlite-crypto-vfs: sqlite-crypto-vfs-arch$(ARCH)
	@echo "*** BUILD SUCCESSFUL ***"

test-build: sqlite-crypto-vfs mkdir-bin
	$(CXX) $(CXXFLAGS) -o bin/test $(SRC_ROOT)/test.cpp

test: test-build
	LD_LIBRARY_PATH=./lib/$(DUMPMACHINE) bin/test

mkdir-bin:
	mkdir -p bin

decrypt-build: mkdir-bin
	$(CXX) -o bin/sqlite-crypto-decrypt $(SRC_ROOT)/aes.c $(SRC_ROOT)/sqlite-crypto-decrypt.cpp

encrypt-build: mkdir-bin
	$(CXX) -o bin/sqlite-crypto-encrypt $(SRC_ROOT)/aes.c $(SRC_ROOT)/sqlite-crypto-encrypt.cpp

shell:
	curl -L https://www.sqlite.org/src/zip/sqlite.zip?r=release -o sqlite.zip
	unzip -o sqlite.zip
	cd sqlite; \
	./configure; \
	patch src/shell.c.in ../shell.patch; \
	patch Makefile ../sqlite_makefile.patch; \
	make sqlite3
