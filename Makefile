CC = gcc
CXX = g++
LD = gcc
CFLAGS = $(shell pkg-config --libs sqlite3) $(shell pkg-config --cflags sqlite3)
ARCH_64 = $(shell gcc -dumpmachine -m64)
ARCH_32 = $(shell gcc -dumpmachine -m32)
ARCH = $(shell gcc -dumpmachine)
CXXFLAGS = -g $(CFLAGS) -lsqlite-crypto-vfs -Llib/$(ARCH)
SQLITE_CRYPTO_VFS_SOURCE = aes.c sqlite-crypto-vfs.c

default: build

clean:
	rm -Rf lib
	rm -f test

build: sqlite-crypto-vfs

sqlite-crypto-vfs-arch64:
	mkdir -p lib/$(ARCH_64)
	$(CC) $(CFLAGS) -shared -m64 -o lib/$(ARCH_64)/libsqlite-crypto-vfs.dylib $(SQLITE_CRYPTO_VFS_SOURCE)

sqlite-crypto-vfs-arch32:
	mkdir -p lib/$(ARCH_32)
	$(CC) $(CFLAGS) -shared -m32 -o lib/$(ARCH_32)/libsqlite-crypto-vfs.dylib $(SQLITE_CRYPTO_VFS_SOURCE)

sqlite-crypto-vfs: sqlite-crypto-vfs-arch32 sqlite-crypto-vfs-arch64
	

test-build: sqlite-crypto-vfs
	$(CXX) $(CXXFLAGS) -o test test.cpp

test: test-build
	./test
