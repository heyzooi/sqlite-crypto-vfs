using System;
using System.Runtime.InteropServices;

namespace SQLiteCryptoVFS
{
    public abstract class SQLiteCryptoVFS
    {
        private const string LibraryName = "sqlite-crypto-vfs";

        [DllImport(LibraryName, EntryPoint = "sqlite_crypto_vfs_name")]
        private static extern IntPtr SQLiteCryptoVFSName();

        [DllImport(LibraryName, EntryPoint = "sqlite_crypto_vfs_register")]
        private static extern int SQLiteCryptoVFSRegister(byte[] key, bool makeDefault);

        public static string VFSName
        {
            get
            {
                return Marshal.PtrToStringAnsi(SQLiteCryptoVFSName());
            }
        }

        public static int RegisterVFS(byte[] key, bool makeDefault = false)
        {
            if (key.Length != 32) throw new ArgumentException("Key must have 32 bytes", nameof(key));
            return SQLiteCryptoVFSRegister(key, makeDefault);
        }

    }
}
