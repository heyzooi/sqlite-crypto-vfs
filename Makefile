CC = gcc
CXX = g++
LD = gcc
CFLAGS = $(shell pkg-config --libs sqlite3) $(shell pkg-config --cflags sqlite3)
CXXFLAGS = -g $(CFLAGS) -lsqlite-crypto-vfs -L.

default: build

build: sqlite-crypto-vfs

sqlite-crypto-vfs:
	$(CC) $(CFLAGS) -shared -o libsqlite-crypto-vfs.dylib aes.c sqlite-crypto-vfs.c

test-build: sqlite-crypto-vfs
	$(CXX) $(CXXFLAGS) -o test test.cpp

test: test-build
	DYLD_LIBRARY_PATH=tiny-AES-c ./test
