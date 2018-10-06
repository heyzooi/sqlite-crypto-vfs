import Foundation
import CSQLiteCryptoVFS

public var vfsName: String {
    return String(cString: sqlite_crypto_vfs_name())
}

public func registerVFS(
    key: Data,
    initializationVector: Data,
    makeDefault: Bool = false
) throws -> Int32 {
    return try registerVFS(
        key: [UInt8](key),
        initializationVector: [UInt8](initializationVector),
        makeDefault: makeDefault
    )
}

public func registerVFS(
    key: [UInt8],
    initializationVector: [UInt8],
    makeDefault: Bool = false
) throws -> Int32 {
    guard key.count == 32 else {
        throw SQLiteCryptoVFSError.invalidKey(key: key)
    }
    guard initializationVector.count == 16 else {
        throw SQLiteCryptoVFSError.invalidInitializationVector(initializationVector: initializationVector)
    }
    let result = sqlite_crypto_vfs_register(key, initializationVector, makeDefault ? 1 : 0)
    return result
}

public enum SQLiteCryptoVFSError: Error {
    
    case invalidKey(key: [UInt8])
    case invalidInitializationVector(initializationVector: [UInt8])
    
    public var localizedDescription: String {
        return "\(failureReason!). \(recoverySuggestion!)."
    }
    
}

extension SQLiteCryptoVFSError: LocalizedError {
    
    public var errorDescription: String? {
        return localizedDescription
    }
    
    public var failureReason: String? {
        switch self {
        case .invalidKey(let key):
            return "Key \(key.hexDebugDescription) is not valid"
        case .invalidInitializationVector(let initializationVector):
            return "Initialization Vector \(initializationVector.hexDebugDescription) is not valid"
        }
    }
    
    public var recoverySuggestion: String? {
        switch self {
        case .invalidKey:
            return "Key must have 32 bytes"
        case .invalidInitializationVector:
            return "Initialization Vector must have 16 bytes"
        }
    }
    
    public var helpAnchor: String? {
        return localizedDescription
    }
    
}

extension SQLiteCryptoVFSError: CustomStringConvertible {
    
    public var description: String {
        return localizedDescription
    }
    
}

extension SQLiteCryptoVFSError: CustomDebugStringConvertible {
    
    public var debugDescription: String {
        return localizedDescription
    }
    
}

extension Array where Element == UInt8 {
    
    var hexDescription: String {
        let str = self.map { (byte) -> String in
            let str = String(byte, radix: 16)
            return str.count < 2 ? "0\(str)" : str
        }
        return "[\(str.joined(separator: " "))]"
    }
    
    var hexDebugDescription: String {
        return "\(hexDescription)(\(self.count) bytes)"
    }
    
}
