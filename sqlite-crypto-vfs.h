#ifndef _SQLITE_CRYPTO_VFS_H_

#include <stdlib.h>

int sqlite_crypto_vfs_register(uint8_t key[32], uint8_t initialization_vector[16], const char* vfs_name, int make_default);

#endif //_SQLITE_CRYPTO_VFS_H_
