import Foundation

public enum EncryptionType: Int, Sendable, CaseIterable {
    case aesCbc256_B64 = 0                       // deprecated, decryption blocked
    case aesCbc128_HmacSha256_B64 = 1
    case aesCbc256_HmacSha256_B64 = 2            // current symmetric format
    case rsa2048_OaepSha256_B64 = 3
    case rsa2048_OaepSha1_B64 = 4                // active asymmetric (org keys)
    case rsa2048_OaepSha256_HmacSha256_B64 = 5
    case rsa2048_OaepSha1_HmacSha256_B64 = 6
    case coseEncrypt0_B64 = 7                    // account crypto v2 — soft-fail only
}

// Test/utility helper kept in the module so tests can assert hex.
extension Data {
    var hexString: String { map { String(format: "%02x", $0) }.joined() }

    init(hex: String) {
        var bytes = [UInt8]()
        bytes.reserveCapacity(hex.count / 2)
        var idx = hex.startIndex
        while idx < hex.endIndex {
            let next = hex.index(idx, offsetBy: 2, limitedBy: hex.endIndex) ?? hex.endIndex
            if let b = UInt8(hex[idx..<next], radix: 16) { bytes.append(b) }
            idx = next
        }
        self = Data(bytes)
    }
}
