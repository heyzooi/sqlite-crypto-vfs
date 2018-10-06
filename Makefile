CC = gcc
CXX = g++
UNAME = $(shell uname)
CFLAGS = $(shell pkg-config --libs sqlite3) $(shell pkg-config --cflags sqlite3) -fPIC
ARCH = $(shell getconf LONG_BIT)
DUMPMACHINE = $(shell $(CC) -dumpmachine -m$(ARCH))
CXXFLAGS = -g $(CFLAGS) -lsqlite-crypto-vfs -Llib/$(DUMPMACHINE)
SQLITE_CRYPTO_VFS_SOURCE = aes.c sqlite-crypto-vfs.c

ifeq ($(UNAME), Linux)
LIB_PREFIX = lib
LIB_SUFFIX = .so
endif
ifeq ($(UNAME), Darwin)
LIB_PREFIX = lib
LIB_SUFFIX = .dylib
endif

default: build

clean:
	rm -Rf lib
	rm -f test

build: sqlite-crypto-vfs

sqlite-crypto-vfs-arch64:
	mkdir -p lib/$(DUMPMACHINE)
	$(CC) $(CFLAGS) -shared -m64 -o lib/$(DUMPMACHINE)/$(LIB_PREFIX)sqlite-crypto-vfs$(LIB_SUFFIX) $(SQLITE_CRYPTO_VFS_SOURCE)

sqlite-crypto-vfs-arch32:
	mkdir -p lib/$(DUMPMACHINE)
	$(CC) $(CFLAGS) -shared -m32 -o lib/$(DUMPMACHINE)/$(LIB_PREFIX)sqlite-crypto-vfs$(LIB_SUFFIX) $(SQLITE_CRYPTO_VFS_SOURCE)

sqlite-crypto-vfs: sqlite-crypto-vfs-arch$(ARCH)
	@echo "*** BUILD SUCCESSFUL ***"

test-build: sqlite-crypto-vfs
	$(CXX) $(CXXFLAGS) -o test test.cpp

test: test-build
	LD_LIBRARY_PATH=./lib/$(DUMPMACHINE) ./test
