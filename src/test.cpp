#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <stdio.h>
#include <sqlite3.h>
#include <unistd.h>
#include <cstring>
#include <vector>
#include "sqlite-crypto-vfs.hpp"
#include "sqlite-crypto-tools.hpp"

#define LOGGER_INFO __FILE__ << ":" << __LINE__ << " "

int test (const char* filename, const char* vfs_name = NULL)
{
    char cwd[1024];
    getcwd(cwd, sizeof(cwd));
    std::cout << "Path: " << cwd << std::endl;
    
    sqlite3 *db = NULL;
    char *zErrMsg = NULL;
    int rc;

    const uint8_t key[32] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };

    rc = sqlite_crypto_vfs_register(key, 0);
    if (rc != SQLITE_OK) {
        return EXIT_FAILURE;
    }
    
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
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        std::cerr << LOGGER_INFO << rc << std::endl;
        return EXIT_FAILURE;
    }

    rc = sqlite3_exec(db, "CREATE TABLE USER (_ID TEXT)", NULL, NULL, &zErrMsg);
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
        if (vfs_name != NULL && !rc) {
            std::cerr << LOGGER_INFO << "SQLite file is not encrypted" << std::endl;
            return EXIT_FAILURE;
        } else if (vfs_name == NULL && rc) {
            std::cerr << LOGGER_INFO << "SQLite file is encrypted" << std::endl;
            return EXIT_FAILURE;
        }
    }
    ifs.close();

    return EXIT_SUCCESS;
}

int compare_files(std::string f1, std::string f2)
{
    std::ifstream ifs1(f1, std::ifstream::ate | std::ifstream::binary);
    std::ifstream ifs2(f2, std::ifstream::ate | std::ifstream::binary);
    
    if (ifs1.tellg() != ifs2.tellg()) {
        ifs1.close();
        ifs2.close();
        return EXIT_FAILURE;
    }
    
    ifs1.seekg(0);
    ifs2.seekg(0);
    
    const size_t buffer_size = AES_BLOCKLEN;
    char buffer1[buffer_size];
    char buffer2[buffer_size];
    int exit = EXIT_SUCCESS;
    while (ifs1.read(buffer1, buffer_size) && ifs2.read(buffer2, buffer_size)) {
        for (int i = 0; i < buffer_size; i++) {
            if (buffer1[i] != buffer2[i]) {
                exit = EXIT_FAILURE;
                goto done;
            }
        }
    }
done:
    ifs1.close();
    ifs2.close();
    
    return exit;
}

int main (int argc, char *argv[])
{
    const std::string original   = "test.db";
    const std::string decrypted  = "test-decrypted.db";
    const std::string encrypted  = "test-encrypted.db";
    const std::string encrypted2 = "test-encrypted2.db";
    
    int exit = test(original.c_str());
    exit    |= test(encrypted.c_str(), sqlite_crypto_vfs_name());
    
    const std::string key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
    
    std::vector<std::string> args;
    
    args.push_back("");
    args.push_back(encrypted);
    args.push_back(decrypted);
    args.push_back(key);
    run(args, AES_ECB_decrypt, "Decrypted file: ");
    exit |= compare_files(original, decrypted);
    
    args.clear();
    
    args.push_back("");
    args.push_back(original);
    args.push_back(encrypted2);
    args.push_back(key);
    run(args, AES_ECB_encrypt, "Encrypted file: ");
    exit |= compare_files(encrypted, encrypted2);
    
    return exit;
}
