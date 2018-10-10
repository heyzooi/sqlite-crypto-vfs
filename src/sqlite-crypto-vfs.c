#include "sqlite-crypto-vfs.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sqlite3.h>
#include <inttypes.h>

#define AES256 1

#include "aes.h"

#if AES_KEYLEN != 32
    #error "#define AES256 1" is missing
#endif

typedef struct Crypto_VFS
{
	sqlite3_vfs base;
    sqlite3_vfs* pVfs;
    uint8_t key[32];
} Crypto_VFS;

typedef struct Crypto_File
{
    sqlite3_file base;
    sqlite3_file* pFile;
    struct AES_ctx ctx;
} Crypto_File;

#define REALVFS(p) (((Crypto_VFS*)(p))->pVfs)
#define REALFILE(p) (((Crypto_File*)(p))->pFile)

static int crypto_vfs_open(sqlite3_vfs* pVfs, const char* zName, sqlite3_file* pFile, int flags, int* pOutFlags);
static int crypto_vfs_delete(sqlite3_vfs* pVfs, const char* zName, int syncDir);
static int crypto_vfs_access(sqlite3_vfs* pVfs, const char* zName, int flags, int* pResOut);
static int crypto_vfs_full_pathname(sqlite3_vfs* pVfs, const char* zName, int nOut, char* zOut);
static void* crypto_vfs_dl_open(sqlite3_vfs* pVfs, const char* zFilename);
static void crypto_vfs_dl_error(sqlite3_vfs* pVfs, int nByte, char* zErrMsg);
static void (*crypto_vfs_dl_sym(sqlite3_vfs *pVfs, void *p, const char*zSym))(void);
static void crypto_vfs_dl_close(sqlite3_vfs*, void*);
static int crypto_vfs_randomness(sqlite3_vfs*, int nByte, char *zOut);
static int crypto_vfs_sleep(sqlite3_vfs*, int microseconds);
static int crypto_vfs_current_time(sqlite3_vfs*, double*);
static int crypto_vfs_get_last_error(sqlite3_vfs*, int, char *);
static int crypto_vfs_current_time_int64(sqlite3_vfs*, sqlite3_int64*);

static int sqlite_crypto_io_close(sqlite3_file*);
static int sqlite_crypto_io_read(sqlite3_file*, void*, int iAmt, sqlite3_int64 iOfst);
static int sqlite_crypto_io_write(sqlite3_file*,const void*,int iAmt, sqlite3_int64 iOfst);
static int sqlite_crypto_io_truncate(sqlite3_file*, sqlite3_int64 size);
static int sqlite_crypto_io_sync(sqlite3_file*, int flags);
static int sqlite_crypto_io_file_size(sqlite3_file*, sqlite3_int64 *pSize);
static int sqlite_crypto_io_lock(sqlite3_file*, int);
static int sqlite_crypto_io_unlock(sqlite3_file*, int);
static int sqlite_crypto_io_check_reserved_lock(sqlite3_file*, int *pResOut);
static int sqlite_crypto_io_file_control(sqlite3_file*, int op, void *pArg);
static int sqlite_crypto_io_sector_size(sqlite3_file*);
static int sqlite_crypto_io_device_characteristics(sqlite3_file*);
static int sqlite_crypto_io_shm_map(sqlite3_file*, int iPg, int pgsz, int, void volatile**);
static int sqlite_crypto_io_shm_lock(sqlite3_file*, int offset, int n, int flags);
static void sqlite_crypto_io_shm_barrier(sqlite3_file*);
static int sqlite_crypto_io_shm_unmap(sqlite3_file*, int deleteFlag);
static int sqlite_crypto_io_fetch(sqlite3_file*, sqlite3_int64 iOfst, int iAmt, void **pp);
static int sqlite_crypto_io_unfetch(sqlite3_file*, sqlite3_int64 iOfst, void *p);

void sqlite_crypto_debug(const void* buffer, int count);

#define SQLITE_CRYPTO_VFS_NAME ("sqlite-crypto")

const char* sqlite_crypto_vfs_name() {
    return SQLITE_CRYPTO_VFS_NAME;
}

static Crypto_VFS crypto_vfs = {
    {
        1,                              /* iVersion */
        0,                              /* szOsFile (set by register_vlog()) */
        1024,                           /* mxPathname */
        0,                              /* pNext */
        SQLITE_CRYPTO_VFS_NAME,         /* zName */
        0,                              /* pAppData */
        crypto_vfs_open,                /* xOpen */
        crypto_vfs_delete,              /* xDelete */
        crypto_vfs_access,              /* xAccess */
        crypto_vfs_full_pathname,       /* xFullPathname */
        crypto_vfs_dl_open,             /* xDlOpen */
        crypto_vfs_dl_error,            /* xDlError */
        crypto_vfs_dl_sym,              /* xDlSym */
        crypto_vfs_dl_close,            /* xDlClose */
        crypto_vfs_randomness,          /* xRandomness */
        crypto_vfs_sleep,               /* xSleep */
        crypto_vfs_current_time,        /* xCurrentTime */
        crypto_vfs_get_last_error,      /* xGetLastError */
        crypto_vfs_current_time_int64   /* xCurrentTimeInt64 */
    },
    NULL
};

static sqlite3_io_methods sqlite_crypto_io_methods = {
    1,                                  /* iVersion */
    sqlite_crypto_io_close,                    /* xClose */
    sqlite_crypto_io_read,                     /* xRead */
    sqlite_crypto_io_write,                    /* xWrite */
    sqlite_crypto_io_truncate,                 /* xTruncate */
    sqlite_crypto_io_sync,                     /* xSync */
    sqlite_crypto_io_file_size,                /* xFileSize */
    sqlite_crypto_io_lock,                     /* xLock */
    sqlite_crypto_io_unlock,                   /* xUnlock */
    sqlite_crypto_io_check_reserved_lock,      /* xCheckReservedLock */
    sqlite_crypto_io_file_control,             /* xFileControl */
    sqlite_crypto_io_sector_size,              /* xSectorSize */
    sqlite_crypto_io_device_characteristics,   /* xDeviceCharacteristics */
    sqlite_crypto_io_shm_map,                  /* xShmMap */
    sqlite_crypto_io_shm_lock,                 /* xShmLock */
    sqlite_crypto_io_shm_barrier,              /* xShmBarrier */
    sqlite_crypto_io_shm_unmap,                /* xShmUnmap */
    sqlite_crypto_io_fetch,                    /* xFetch */
    sqlite_crypto_io_unfetch,                  /* xUnfetch */
};

int sqlite_crypto_vfs_register(const uint8_t key[32], const int make_default)
{
    sqlite3_vfs* root_vfs = sqlite3_vfs_find(NULL);
    if (!root_vfs) {
        return SQLITE_NOTFOUND;
    }
    crypto_vfs.pVfs = root_vfs;
    crypto_vfs.base.szOsFile = sizeof(Crypto_File) + root_vfs->szOsFile;
    memcpy(crypto_vfs.key, key, sizeof(uint8_t) * 32);
    int result = sqlite3_vfs_register(&crypto_vfs.base, make_default);
    return result;
}

static int crypto_vfs_open(
    sqlite3_vfs *pVfs,
    const char *zName,
    sqlite3_file *pFile,
    int flags,
    int *pOutFlags
) {
    Crypto_VFS *pCrypto_VFS = (Crypto_VFS*) pVfs;
    Crypto_File *pCrypto_File = (Crypto_File*) pFile;
    pCrypto_File->pFile = (sqlite3_file*) &pCrypto_File[1];
    AES_init_ctx(&(pCrypto_File->ctx), pCrypto_VFS->key);
    int rc = REALVFS(pVfs)->xOpen(REALVFS(pVfs), zName, pCrypto_File->pFile, flags, pOutFlags);
    if (rc == SQLITE_OK) {
        pFile->pMethods = &sqlite_crypto_io_methods;
    }
    return rc;
}

static int crypto_vfs_delete(
    sqlite3_vfs* pVfs,
    const char* zName,
    int syncDir
) {
    return REALVFS(pVfs)->xDelete(REALVFS(pVfs), zName, syncDir);
}

static int crypto_vfs_access(
    sqlite3_vfs* pVfs,
    const char* zName,
    int flags,
    int* pResOut
) {
    return REALVFS(pVfs)->xAccess(REALVFS(pVfs), zName, flags, pResOut);
}

static int crypto_vfs_full_pathname(
    sqlite3_vfs* pVfs,
    const char* zName,
    int nOut,
    char* zOut
) {
    return REALVFS(pVfs)->xFullPathname(REALVFS(pVfs), zName, nOut, zOut);
}

static void* crypto_vfs_dl_open(
    sqlite3_vfs* pVfs,
    const char* zFilename
) {
    return REALVFS(pVfs)->xDlOpen(REALVFS(pVfs), zFilename);
}

static void crypto_vfs_dl_error(
    sqlite3_vfs* pVfs,
    int nByte,
    char* zErrMsg
) {
    REALVFS(pVfs)->xDlError(REALVFS(pVfs), nByte, zErrMsg);
}

static void (*crypto_vfs_dl_sym(sqlite3_vfs *pVfs, void *p, const char*zSym))(void)
{
    return REALVFS(pVfs)->xDlSym(REALVFS(pVfs), p, zSym);
}

static void crypto_vfs_dl_close(sqlite3_vfs* pVfs, void* p)
{
    REALVFS(pVfs)->xDlClose(REALVFS(pVfs), p);
}

static int crypto_vfs_randomness(
    sqlite3_vfs* pVfs,
    int nByte,
    char *zOut
) {
    return REALVFS(pVfs)->xRandomness(REALVFS(pVfs), nByte, zOut);
}

static int crypto_vfs_sleep(
    sqlite3_vfs* pVfs,
    int microseconds
) {
    return REALVFS(pVfs)->xSleep(REALVFS(pVfs), microseconds);
}

static int crypto_vfs_current_time(
    sqlite3_vfs* pVfs,
    double* pOut
) {
    return REALVFS(pVfs)->xCurrentTime(REALVFS(pVfs), pOut);
}

static int crypto_vfs_get_last_error(
    sqlite3_vfs* pVfs,
    int code,
    char* pOut
) {
    return REALVFS(pVfs)->xGetLastError(REALVFS(pVfs), code, pOut);
}

static int crypto_vfs_current_time_int64(
    sqlite3_vfs* pVfs,
    sqlite3_int64* pOut
) {
    return REALVFS(pVfs)->xCurrentTimeInt64(REALVFS(pVfs), pOut);
}

static int sqlite_crypto_io_close(sqlite3_file* pFile)
{
    return REALFILE(pFile)->pMethods->xClose(REALFILE(pFile));
}

void sqlite_crypto_debug(
    const void* buffer,
    int count
) {
    uint8_t* buffer_u8 = (uint8_t*) buffer;
    for (int i = 0; i < count; i++) {
        printf("%02x ", buffer_u8[i]);
    }
    printf("\n");
}

void sqlite_crypto_decrypt(
    struct AES_ctx* ctx,
    void* buffer,
    int count
) {
    const int n = count / AES_BLOCKLEN;
    for (int i = 0; i < n; i++) {
        AES_ECB_decrypt(ctx, buffer + (i * AES_BLOCKLEN));
    }
}

static int sqlite_crypto_io_read(
    sqlite3_file* pFile,
    void* buffer,
    int count,
    sqlite3_int64 offset
) {
    int rc = REALFILE(pFile)->pMethods->xRead(REALFILE(pFile), buffer, count, offset);
    if (rc == SQLITE_IOERR_SHORT_READ) {
        return rc;
    }
    Crypto_File *pCrypto_File = (Crypto_File*) pFile;
    const int offset_diff = offset % AES_BLOCKLEN;
    const int count_diff = count % AES_BLOCKLEN;
    if (offset_diff || count_diff) {
        const sqlite3_int64 prev_offset = offset - offset_diff;
        const int remaining_count = count - offset_diff;
        const int remaining_count_diff = remaining_count % AES_BLOCKLEN;
        const int block_size = (offset_diff ? AES_BLOCKLEN : 0) + (remaining_count - remaining_count_diff) + (remaining_count_diff ? AES_BLOCKLEN : 0);
        uint8_t block[block_size];
        rc = REALFILE(pFile)->pMethods->xRead(REALFILE(pFile), block, block_size, prev_offset);
        if (rc == SQLITE_IOERR_SHORT_READ) {
            return rc;
        }
        sqlite_crypto_decrypt(&(pCrypto_File->ctx), block, block_size);
        if (offset_diff) {
            memcpy(buffer, block + AES_BLOCKLEN - offset_diff, count);
        } else {
            memcpy(buffer, block, count);
        }
    } else {
        sqlite_crypto_decrypt(&(pCrypto_File->ctx), buffer, count);
    }
    return rc;
}

void sqlite_crypto_encrypt(
    struct AES_ctx* ctx,
    void* buffer,
    int count
) {
    const int n = count / AES_BLOCKLEN;
    for (int i = 0; i < n; i++) {
        AES_ECB_encrypt(ctx, buffer + (i * AES_BLOCKLEN));
    }
}

static int sqlite_crypto_io_write(
    sqlite3_file* pFile,
    const void* buffer,
    int count,
    sqlite3_int64 offset
) {
    Crypto_File *pCrypto_File = (Crypto_File*) pFile;
    const int offset_diff = offset % AES_BLOCKLEN;
    const int count_diff = count % AES_BLOCKLEN;
    if (offset_diff || count_diff) {
        const sqlite3_int64 prev_offset = offset - offset_diff;
        const int remaining_count = count - offset_diff;
        const int remaining_count_diff = remaining_count % AES_BLOCKLEN;
        const int block_size = (offset_diff ? AES_BLOCKLEN : 0) + (remaining_count - remaining_count_diff) + (remaining_count_diff ? AES_BLOCKLEN : 0);
        uint8_t block[block_size];
        memset(block, 0, block_size);
        int rc = SQLITE_OK;
        const int n_blocks = block_size / AES_BLOCKLEN;
        for (int i = 0; i < n_blocks && rc != SQLITE_IOERR_SHORT_READ; i++) {
            rc = sqlite_crypto_io_read(pFile, block, block_size, prev_offset);
        }
        if (offset_diff) {
            memcpy(block, buffer + AES_BLOCKLEN - offset_diff, count);
        } else {
            memcpy(block, buffer, count);
        }
        sqlite_crypto_encrypt(&(pCrypto_File->ctx), block, block_size);
        return REALFILE(pFile)->pMethods->xWrite(REALFILE(pFile), block, block_size, prev_offset);
    } else {
        uint8_t enc_buf[count];
        memcpy(enc_buf, buffer, count);
        sqlite_crypto_encrypt(&(pCrypto_File->ctx), enc_buf, count);
        return REALFILE(pFile)->pMethods->xWrite(REALFILE(pFile), enc_buf, count, offset);
    }
}

static int sqlite_crypto_io_truncate(
    sqlite3_file* pFile,
    sqlite3_int64 size
) {
    return REALFILE(pFile)->pMethods->xTruncate(REALFILE(pFile), size);
}

static int sqlite_crypto_io_sync(
    sqlite3_file* pFile,
    int flags
) {
    return REALFILE(pFile)->pMethods->xSync(REALFILE(pFile), flags);
}

static int sqlite_crypto_io_file_size(
    sqlite3_file* pFile,
    sqlite3_int64 *pSize
) {
    return REALFILE(pFile)->pMethods->xFileSize(REALFILE(pFile), pSize);
}

static int sqlite_crypto_io_lock(
    sqlite3_file* pFile,
    int lock
) {
    return REALFILE(pFile)->pMethods->xLock(REALFILE(pFile), lock);
}

static int sqlite_crypto_io_unlock(
    sqlite3_file* pFile,
    int lock
) {
    return REALFILE(pFile)->pMethods->xUnlock(REALFILE(pFile), lock);
}

static int sqlite_crypto_io_check_reserved_lock(
    sqlite3_file* pFile,
    int *pResOut
) {
    return REALFILE(pFile)->pMethods->xCheckReservedLock(REALFILE(pFile), pResOut);
}

static int sqlite_crypto_io_file_control(
    sqlite3_file* pFile,
    int op,
    void *pArg
) {
    return REALFILE(pFile)->pMethods->xFileControl(REALFILE(pFile), op, pArg);
}

static int sqlite_crypto_io_sector_size(sqlite3_file* pFile)
{
    return REALFILE(pFile)->pMethods->xSectorSize(REALFILE(pFile));
}

static int sqlite_crypto_io_device_characteristics(sqlite3_file* pFile)
{
    return REALFILE(pFile)->pMethods->xDeviceCharacteristics(REALFILE(pFile));
}

static int sqlite_crypto_io_shm_map(
    sqlite3_file* pFile,
    int iPg,
    int pgsz,
    int map,
    void volatile** p
) {
    return REALFILE(pFile)->pMethods->xShmMap(REALFILE(pFile), iPg, pgsz, map, p);
}

static int sqlite_crypto_io_shm_lock(
    sqlite3_file* pFile,
    int offset,
    int n,
    int flags
) {
    return REALFILE(pFile)->pMethods->xShmLock(REALFILE(pFile), offset, n, flags);
}

static void sqlite_crypto_io_shm_barrier(sqlite3_file* pFile)
{
    REALFILE(pFile)->pMethods->xShmBarrier(REALFILE(pFile));
}

static int sqlite_crypto_io_shm_unmap(
    sqlite3_file* pFile,
    int deleteFlag
) {
    return REALFILE(pFile)->pMethods->xShmUnmap(REALFILE(pFile), deleteFlag);
}

static int sqlite_crypto_io_fetch(
    sqlite3_file* pFile,
    sqlite3_int64 iOfst,
    int iAmt,
    void **pp
) {
    return REALFILE(pFile)->pMethods->xFetch(REALFILE(pFile), iOfst, iAmt, pp);
}

static int sqlite_crypto_io_unfetch(
    sqlite3_file* pFile,
    sqlite3_int64 iOfst,
    void *p
) {
    return REALFILE(pFile)->pMethods->xUnfetch(REALFILE(pFile), iOfst, p);
}
