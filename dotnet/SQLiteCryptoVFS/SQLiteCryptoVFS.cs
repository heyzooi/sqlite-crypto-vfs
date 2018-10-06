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
        private static extern int SQLiteCryptoVFSRegister(byte[] key, byte[] initializationVector, bool makeDefault);

        public static string VFSName
        {
            get
            {
                return Marshal.PtrToStringAnsi(SQLiteCryptoVFSName());
            }
        }

        public static int RegisterVFS(byte[] key, byte[] initializationVector, bool makeDefault = false)
        {
            if (key.Length != 32) throw new ArgumentException("Key must have 32 bytes", nameof(key));
            if (initializationVector.Length != 16) throw new ArgumentException("Initialization Vector must have 16 bytes", nameof(initializationVector));
            return SQLiteCryptoVFSRegister(key, initializationVector, makeDefault);
        }

    }
}
