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
