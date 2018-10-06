using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using SQLitePCL;
using System.Text;
using System.Diagnostics;

namespace SQLiteCryptoVFS.Tests
{
    [TestClass]
    public class SQLiteCryptoVFSUnitTests
    {
        [TestMethod]
        public void TestKeySize()
        {
            var exception = Assert.ThrowsException<ArgumentException>(() =>
            {
                SQLiteCryptoVFS.RegisterVFS(new byte[] { 10, 20, 30 }, new byte[] { });
            });
            Assert.AreEqual(exception.ParamName, "key");
            Assert.AreEqual(exception.Message, "Key must have 32 bytes\nParameter name: key");
        }

        [TestMethod]
        public void TestInitializationVectorSize()
        {
            var exception = Assert.ThrowsException<ArgumentException>(() =>
            {
                SQLiteCryptoVFS.RegisterVFS(
                    new byte[] {
                        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
                    },
                    new byte[] { 10, 20, 30 }
                );
            });
            Assert.AreEqual(exception.ParamName, "initializationVector");
            Assert.AreEqual(exception.Message, "Initialization Vector must have 16 bytes\nParameter name: initializationVector");
        }

        private Func<string, bool> FilterLibraryFiles(string libraryName)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return (f) => {
                    return Path.GetExtension(f).Equals(".dll");
                };
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                return (f) => {
                    return f.StartsWith("lib", StringComparison.Ordinal) &&
                            Path.GetExtension(f).Equals(".so");
                };
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                return (f) => {
                    return f.StartsWith("lib", StringComparison.Ordinal) &&
                            Path.GetExtension(f).Equals(".dylib");
                };
            }
            return null;
        }

        private void CopyLibrary()
        {
            var arch = Environment.Is64BitProcess ? "-m64" : "-m32";
            var processInfo = new ProcessStartInfo
            {
                FileName = "gcc",
                Arguments = $"-dumpmachine {arch}",
                RedirectStandardOutput = true
            };
            string gccOutput;
            using (var process = Process.Start(processInfo))
            {
                gccOutput = process.StandardOutput.ReadLine();
                process.WaitForExit();
                process.Close();
            }

            var currentDirectory = Directory.GetCurrentDirectory();
            var relativePath = $"../../../../../lib/{gccOutput}";
            var path = Path.Combine(currentDirectory, relativePath);
            var files = Directory.EnumerateFiles(path)
                                 .Select(Path.GetFileName)
                                 .Where(FilterLibraryFiles("sqlite-crypto-vfs")).ToList();
            foreach (var file in files)
            {
                File.Copy(Path.Combine(currentDirectory, relativePath, file), file, true);
                Console.WriteLine($"{file} {new FileInfo(file).Length} bytes");
            }
        }

        [TestMethod]
        public void TestEncryption()
        {
            CopyLibrary();

            var vfsName = SQLiteCryptoVFS.VFSName;

            var resultCode = SQLiteCryptoVFS.RegisterVFS(
                new byte[] {
                    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
                },
                new byte[] {
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
                }
            );
            Assert.AreEqual(resultCode, raw.SQLITE_OK);

            const string filename = "test-encrypted.db";

            raw.SetProvider(new SQLite3Provider_sqlite3());
            Console.WriteLine($"{raw.sqlite3_libversion()}");
            Console.WriteLine($"{raw.sqlite3_libversion_number()}");

            if (File.Exists(filename))
                File.Delete(filename);

            resultCode = raw.sqlite3_open_v2(filename, out sqlite3 db, raw.SQLITE_OPEN_READWRITE | raw.SQLITE_OPEN_CREATE, vfsName);
            //resultCode = raw.sqlite3_open_v2(filename, out sqlite3 db, raw.SQLITE_OPEN_READWRITE | raw.SQLITE_OPEN_CREATE, null);
            Assert.AreEqual(resultCode, raw.SQLITE_OK);
            try
            {
                resultCode = raw.sqlite3_exec(db, "CREATE TABLE USER (_ID TEXT)");
                Assert.AreEqual(resultCode, raw.SQLITE_OK);

                const string plaintext = "Can you keep a secret?";

                {
                    resultCode = raw.sqlite3_prepare_v2(db, "INSERT INTO USER (_ID) VALUES (?)", out sqlite3_stmt stmt);
                    Assert.AreEqual(resultCode, raw.SQLITE_OK);
                    try
                    {
                        resultCode = raw.sqlite3_bind_text(stmt, 1, plaintext);
                        Assert.AreEqual(resultCode, raw.SQLITE_OK);

                        resultCode = raw.sqlite3_step(stmt);
                        Assert.AreEqual(resultCode, raw.SQLITE_DONE);
                    }
                    finally
                    {
                        resultCode = raw.sqlite3_finalize(stmt);
                        Assert.AreEqual(resultCode, raw.SQLITE_OK);
                    }
                }

                {
                    resultCode = raw.sqlite3_prepare_v2(db, "SELECT * FROM USER", out sqlite3_stmt stmt);
                    Assert.AreEqual(resultCode, raw.SQLITE_OK);
                    try
                    {
                        resultCode = raw.sqlite3_step(stmt);
                        Assert.AreEqual(resultCode, raw.SQLITE_ROW);

                        Assert.AreEqual(raw.sqlite3_column_text(stmt, 0), plaintext);
                    }
                    finally
                    {
                        resultCode = raw.sqlite3_finalize(stmt);
                        Assert.AreEqual(resultCode, raw.SQLITE_OK);
                    }
                }

                using (var fs = new FileStream(filename, FileMode.Open, FileAccess.Read))
                {
                    byte[] buffer = new byte[16];
                    fs.Read(buffer, 0, buffer.Length);
                    fs.Close();
                    var header = Encoding.ASCII.GetString(buffer);
                    Assert.AreNotEqual(header, "SQLite format 3\0");
                }
            }
            finally
            {
                resultCode = raw.sqlite3_close_v2(db);
                Assert.AreEqual(resultCode, raw.SQLITE_OK);
            }
        }
    }
}
