#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <stdio.h>
#include <sqlite3.h>
#include <unistd.h>
#include "sqlite-crypto-vfs.hpp"

#define LOGGER_INFO __FILE__ << ":" << __LINE__ << " "

int main (int argc, char *argv[])
{
    char cwd[1024];
    getcwd(cwd, sizeof(cwd));
    std::cout << "Path: " << cwd << std::endl;
    
    sqlite3 *db = NULL;
    char *zErrMsg = NULL;
    int rc;

    uint8_t key[32] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };

    uint8_t initialization_vector[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    const char* vfs_name = "sqlite-crypto";
    rc = sqlite_crypto_vfs_register(key, initialization_vector, vfs_name, 0);
    if (rc != SQLITE_OK) {
        return EXIT_FAILURE;
    }
    
    const char* filename = "test-encrypted.db";
    
    std::ifstream f(filename);
    if (f.good()) {
        f.close();
        if (remove(filename)) {
            std::cerr << LOGGER_INFO << "File can't be deleted" << std::endl;
            return EXIT_FAILURE;
        }
    } else {
        f.close();
    }
    
    rc = sqlite3_open_v2(filename, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, vfs_name);
    //rc = sqlite3_open_v2(filename, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        std::cerr << LOGGER_INFO << rc << std::endl;
        return EXIT_FAILURE;
    }

    rc = sqlite3_exec(db, "CREATE TABLE USER (_ID TEXT PRIMARY KEY)", NULL, NULL, &zErrMsg);
    if (rc != SQLITE_OK) {
        std::cerr << LOGGER_INFO << "SQL Error: " << zErrMsg << std::endl;
        sqlite3_free(zErrMsg);
        return EXIT_FAILURE;
    }

    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, "INSERT INTO USER (_ID) VALUES (?)", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        std::cerr << LOGGER_INFO << "SQL Error: " << sqlite3_errmsg(db) << std::endl;
        return EXIT_FAILURE;
    }

    const char* plaintext = "Can you keep a secret?";
    sqlite3_bind_text(stmt, 1, plaintext, -1, NULL);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << LOGGER_INFO << "SQL Error: " << sqlite3_errmsg(db) << std::endl;
        return EXIT_FAILURE;
    }

    sqlite3_finalize(stmt);

    rc = sqlite3_prepare_v2(db, "SELECT * FROM USER", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        std::cerr << LOGGER_INFO << "SQL Error: " << sqlite3_errmsg(db) << std::endl;
        return EXIT_FAILURE;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        std::cerr << LOGGER_INFO << "SQL Error: " << sqlite3_errmsg(db) << std::endl;
        return EXIT_FAILURE;
    }
    
    if (memcmp(plaintext, sqlite3_column_text(stmt, 0), 2)) {
        std::cerr << LOGGER_INFO << "Data does not match" << std::endl;
        return EXIT_FAILURE;
    }

    rc = sqlite3_close_v2(db);
    if (rc != SQLITE_OK) {
        std::cerr << LOGGER_INFO << "SQL Error: " << sqlite3_errmsg(db) << std::endl;
        return EXIT_FAILURE;
    }
    
    std::ifstream ifs(filename, std::ifstream::in);
    if (ifs.good()) {
        const int buffer_size = 16;
        char buffer[buffer_size];
        ifs.read(buffer, buffer_size);
        rc = strcmp(buffer, "SQLite format 3");
        if (!rc) {
            std::cerr << LOGGER_INFO << "SQLite file not encrypted" << std::endl;
            return EXIT_FAILURE;
        }
    }
    ifs.close();

    return EXIT_SUCCESS;
}
