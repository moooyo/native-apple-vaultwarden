import Foundation
import CommonCrypto

enum PBKDF2 {
    /// PBKDF2-HMAC-SHA256. `password` and `salt` are used as raw bytes.
    static func deriveSHA256(password: Data, salt: Data, iterations: Int, keyLength: Int) throws -> [UInt8] {
        var derived = [UInt8](repeating: 0, count: keyLength)
        // Empty salt/password need a valid (non-nil) pointer; use a 1-byte scratch.
        let status: Int32 = password.withUnsafeBytesOrEmpty { pwPtr, pwLen in
            salt.withUnsafeBytesOrEmpty { saltPtr, saltLen in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    pwPtr.assumingMemoryBound(to: Int8.self), pwLen,
                    saltPtr.assumingMemoryBound(to: UInt8.self), saltLen,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                    UInt32(iterations),
                    &derived, keyLength
                )
            }
        }
        guard status == kCCSuccess else { throw CryptoError.kdfFailed }
        return derived
    }
}

private extension Data {
    /// Calls `body` with a guaranteed non-nil base pointer (uses a scratch byte when empty).
    func withUnsafeBytesOrEmpty<R>(_ body: (UnsafeRawPointer, Int) -> R) -> R {
        if isEmpty {
            var scratch: UInt8 = 0
            return withUnsafePointer(to: &scratch) { body(UnsafeRawPointer($0), 0) }
        }
        return withUnsafeBytes { body($0.baseAddress!, count) }
    }
}
