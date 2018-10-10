#ifndef _SQLITE_CRYPTO_VFS_H_

#include <stdlib.h>
#include <stdint.h>

const char* sqlite_crypto_vfs_name(void);
int sqlite_crypto_vfs_register(const uint8_t key[32], const int make_default);

#endif //_SQLITE_CRYPTO_VFS_H_
