import CommonCrypto
import CryptoKit
import Foundation

public enum SendCryptography {
    public static func contentKey(secret: Data) throws -> SymmetricCryptoKey {
        guard secret.count == 16 else { throw CryptoError.invalidKeyLength }
        let derived = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: secret),
                                             salt: Data("bitwarden-send".utf8), info: Data("send".utf8),
                                             outputByteCount: 64)
        return try derived.withUnsafeBytes { try SymmetricCryptoKey(combined: Data($0)) }
    }

    public static func passwordVerifier(_ password: String, secret: Data) throws -> String {
        guard secret.count == 16 else { throw CryptoError.invalidKeyLength }
        let verifier = try PBKDF2.deriveSHA256(password: Data(password.utf8), salt: secret,
                                               iterations: 100_000, keyLength: 32)
        return Data(verifier).base64EncodedString()
    }

    public static func writeEncryptedFile(from input: FileHandle, to output: FileHandle,
                                          using key: SymmetricCryptoKey, maximumBytes: Int) throws -> Int {
        let iv = try SecureRandom.bytes(kCCBlockSizeAES128)
        var cryptor: CCCryptorRef?
        let status = key.encKey.withUnsafeBytes { keyBytes in
            iv.withUnsafeBytes { ivBytes in
                CCCryptorCreate(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding),
                                keyBytes.baseAddress, keyBytes.count, ivBytes.baseAddress, &cryptor)
            }
        }
        guard status == kCCSuccess, let cryptor else { throw CryptoError.encryptionFailed }
        defer { CCCryptorRelease(cryptor) }
        var authenticator = HMAC<SHA256>(key: SymmetricKey(data: key.macKey))
        authenticator.update(data: iv)
        let start = try output.offset()
        try output.write(contentsOf: Data([2]) + iv + Data(count: 32))

        var totalRead = 0
        while true {
            try Task.checkCancellation()
            guard let chunk = try input.read(upToCount: 64 * 1024), !chunk.isEmpty else { break }
            totalRead += chunk.count
            guard totalRead <= maximumBytes else { throw CocoaError(.fileReadTooLarge) }
            var written = 0
            var ciphertext = Data(count: chunk.count + kCCBlockSizeAES128)
            let result = ciphertext.withUnsafeMutableBytes { target in
                chunk.withUnsafeBytes { source in
                    CCCryptorUpdate(cryptor, source.baseAddress, source.count,
                                    target.baseAddress, target.count, &written)
                }
            }
            guard result == kCCSuccess else { throw CryptoError.encryptionFailed }
            ciphertext.count = written
            authenticator.update(data: ciphertext)
            try output.write(contentsOf: ciphertext)
        }
        var finalBlock = Data(count: kCCBlockSizeAES128)
        var written = 0
        let finalStatus = finalBlock.withUnsafeMutableBytes { target in
            CCCryptorFinal(cryptor, target.baseAddress, target.count, &written)
        }
        guard finalStatus == kCCSuccess else { throw CryptoError.encryptionFailed }
        finalBlock.count = written
        authenticator.update(data: finalBlock)
        try output.write(contentsOf: finalBlock)
        let end = try output.offset()
        try output.seek(toOffset: start + 17)
        try output.write(contentsOf: Data(authenticator.finalize()))
        try output.seek(toOffset: end)
        return Int(end - start)
    }
}
