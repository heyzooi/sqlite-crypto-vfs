import XCTest
import SQLiteCryptoVFS
import SQLite3

final class SQLiteCryptoVFSTests: XCTestCase {
    
    func testKeySize() {
        let key = Data([
            UInt8("60", radix: 16)!, UInt8("3d", radix: 16)!, UInt8("eb", radix: 16)!,
        ])
        let initializationVector = Data()
        do {
            _ = try SQLiteCryptoVFS.registerVFS(
                key: key,
                initializationVector: initializationVector
            )
            XCTFail("Key should be invalid")
        } catch {
            XCTAssertEqual(error.localizedDescription, "Key [60 3d eb](3 bytes) is not valid. Key must have 32 bytes.")
        }
    }
    
    func testInitializationVectorSize() {
        let key = Data([
            UInt8("60", radix: 16)!, UInt8("3d", radix: 16)!, UInt8("eb", radix: 16)!, UInt8("10", radix: 16)!, UInt8("15", radix: 16)!, UInt8("ca", radix: 16)!, UInt8("71", radix: 16)!, UInt8("be", radix: 16)!,
            UInt8("2b", radix: 16)!, UInt8("73", radix: 16)!, UInt8("ae", radix: 16)!, UInt8("f0", radix: 16)!, UInt8("85", radix: 16)!, UInt8("7d", radix: 16)!, UInt8("77", radix: 16)!, UInt8("81", radix: 16)!,
            UInt8("1f", radix: 16)!, UInt8("35", radix: 16)!, UInt8("2c", radix: 16)!, UInt8("07", radix: 16)!, UInt8("3b", radix: 16)!, UInt8("61", radix: 16)!, UInt8("08", radix: 16)!, UInt8("d7", radix: 16)!,
            UInt8("2d", radix: 16)!, UInt8("98", radix: 16)!, UInt8("10", radix: 16)!, UInt8("a3", radix: 16)!, UInt8("09", radix: 16)!, UInt8("14", radix: 16)!, UInt8("df", radix: 16)!, UInt8("f4", radix: 16)!,
        ])
        let initializationVector = Data([
            UInt8("00", radix: 16)!, UInt8("01", radix: 16)!, UInt8("02", radix: 16)!,
        ])
        do {
            _ = try SQLiteCryptoVFS.registerVFS(
                key: key,
                initializationVector: initializationVector
            )
            XCTFail("Key should be invalid")
        } catch {
            XCTAssertEqual(error.localizedDescription, "Initialization Vector [00 01 02](3 bytes) is not valid. Initialization Vector must have 16 bytes.")
        }
    }
    
    func testEncryption() {
        let key = Data([
            UInt8("60", radix: 16)!, UInt8("3d", radix: 16)!, UInt8("eb", radix: 16)!, UInt8("10", radix: 16)!, UInt8("15", radix: 16)!, UInt8("ca", radix: 16)!, UInt8("71", radix: 16)!, UInt8("be", radix: 16)!,
            UInt8("2b", radix: 16)!, UInt8("73", radix: 16)!, UInt8("ae", radix: 16)!, UInt8("f0", radix: 16)!, UInt8("85", radix: 16)!, UInt8("7d", radix: 16)!, UInt8("77", radix: 16)!, UInt8("81", radix: 16)!,
            UInt8("1f", radix: 16)!, UInt8("35", radix: 16)!, UInt8("2c", radix: 16)!, UInt8("07", radix: 16)!, UInt8("3b", radix: 16)!, UInt8("61", radix: 16)!, UInt8("08", radix: 16)!, UInt8("d7", radix: 16)!,
            UInt8("2d", radix: 16)!, UInt8("98", radix: 16)!, UInt8("10", radix: 16)!, UInt8("a3", radix: 16)!, UInt8("09", radix: 16)!, UInt8("14", radix: 16)!, UInt8("df", radix: 16)!, UInt8("f4", radix: 16)!,
        ])
        let initializationVector = Data([
            UInt8("00", radix: 16)!, UInt8("01", radix: 16)!, UInt8("02", radix: 16)!, UInt8("03", radix: 16)!, UInt8("04", radix: 16)!, UInt8("05", radix: 16)!, UInt8("06", radix: 16)!, UInt8("07", radix: 16)!,
            UInt8("08", radix: 16)!, UInt8("09", radix: 16)!, UInt8("0a", radix: 16)!, UInt8("0b", radix: 16)!, UInt8("0c", radix: 16)!, UInt8("0d", radix: 16)!, UInt8("0e", radix: 16)!, UInt8("0f", radix: 16)!,
        ])
        do {
            let vfsName = SQLiteCryptoVFS.vfsName
            var resultCode = try SQLiteCryptoVFS.registerVFS(
                key: key,
                initializationVector: initializationVector
            )
            
            guard resultCode == SQLITE_OK else {
                XCTFail("VFS not registered. Result code: \(resultCode)")
                return
            }
            
            let filename = "test-encrypted.db"
            
            let fileManager = FileManager.default
            print("Path: \(fileManager.currentDirectoryPath)")
            if fileManager.fileExists(atPath: filename) {
                try fileManager.removeItem(atPath: filename)
            }
            
            var db: OpaquePointer?
            resultCode = sqlite3_open_v2(filename, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, vfsName)
//            resultCode = sqlite3_open_v2(filename, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nil)
            defer {
                sqlite3_close_v2(db)
            }
            guard resultCode == SQLITE_OK else {
                XCTFail("Can't open SQLite. Result code: \(resultCode) / \(sqlite3_extended_errcode(db))")
                return
            }
            
            var zErrMsg: UnsafeMutablePointer<CChar>? = nil
            resultCode = sqlite3_exec(db, "CREATE TABLE USER (_ID TEXT PRIMARY KEY)", nil, nil, &zErrMsg)
            guard resultCode == SQLITE_OK else {
                XCTFail("SQL Error: \(String(cString: zErrMsg!))")
                sqlite3_free(zErrMsg)
                return
            }
            
            let plaintext = "Can you keep a secret?"
            
            do {
                var stmt: OpaquePointer?
                resultCode = sqlite3_prepare_v2(db, "INSERT INTO USER (_ID) VALUES (?)", -1, &stmt, nil)
                defer {
                    resultCode = sqlite3_finalize(stmt)
                    if resultCode != SQLITE_OK {
                        XCTFail("SQL Error: \(String(cString: sqlite3_errmsg(db)))")
                    }
                }
                guard resultCode == SQLITE_OK else {
                    XCTFail("SQL Error: \(String(cString: sqlite3_errmsg(db)))")
                    return
                }
                
                resultCode = sqlite3_bind_text(stmt, 1, plaintext, -1, nil)
                guard resultCode == SQLITE_OK else {
                    XCTFail("SQL Error: \(String(cString: sqlite3_errmsg(db)))")
                    return
                }
                
                resultCode = sqlite3_step(stmt)
                guard resultCode == SQLITE_DONE else {
                    XCTFail("SQL Error: \(String(cString: sqlite3_errmsg(db)))")
                    return
                }
            }
            
            do {
                var stmt: OpaquePointer?
                resultCode = sqlite3_prepare_v2(db, "SELECT * FROM USER", -1, &stmt, nil)
                defer {
                    resultCode = sqlite3_finalize(stmt)
                    if resultCode != SQLITE_OK {
                        XCTFail("SQL Error: \(String(cString: sqlite3_errmsg(db)))")
                    }
                }
                guard resultCode == SQLITE_OK else {
                    XCTFail("SQL Error: \(String(cString: sqlite3_errmsg(db)))")
                    return
                }
                
                resultCode = sqlite3_step(stmt);
                guard resultCode == SQLITE_ROW else {
                    XCTFail("SQL Error: \(String(cString: sqlite3_errmsg(db)))")
                    return
                }
                
                XCTAssertEqual(String(cString: sqlite3_column_text(stmt, 0)), plaintext)
            }
            
            let _fileHandle = FileHandle(forReadingAtPath: filename)
            XCTAssertNotNil(_fileHandle)
            guard let fileHandle = _fileHandle else {
                return
            }
            defer {
                fileHandle.closeFile()
            }
            let data = fileHandle.readData(ofLength: 16)
            let header = String(data: data, encoding: .ascii)
            XCTAssertNotEqual(header, "SQLite format 3\0")
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    static var allTests = [
        ("testKeySize", testKeySize),
        ("testInitializationVectorSize", testInitializationVectorSize),
        ("testEncryption", testEncryption),
    ]
    
}
