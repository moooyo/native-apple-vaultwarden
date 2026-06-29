import Foundation
import CommonCrypto
import CryptoKit

public enum SymmetricCrypto {
    /// Encrypt with AES-256-CBC (PKCS#7) then HMAC-SHA256 over (iv || ciphertext).
    public static func encrypt(_ plaintext: Data, using key: SymmetricCryptoKey) throws -> EncString {
        let iv = try SecureRandom.bytes(16)
        let ciphertext = try aesCBC(.encrypt, data: plaintext, key: key.encKey, iv: iv)
        let mac = hmac(iv + ciphertext, key: key.macKey)
        return EncString(type: .aesCbc256_HmacSha256_B64, iv: iv, ciphertext: ciphertext, mac: mac)
    }

    /// Verify HMAC BEFORE decrypting (encrypt-then-MAC); only type 2 is supported here.
    ///
    /// `HMAC<SHA256>.isValidAuthenticationCode` performs the required constant-time
    /// comparison of the MAC. It MUST NOT be replaced with `==` on `Data`, which would
    /// short-circuit and leak timing information enabling a MAC-forgery oracle.
    public static func decrypt(_ encString: EncString, using key: SymmetricCryptoKey) throws -> Data {
        guard encString.type == .aesCbc256_HmacSha256_B64 else {
            throw CryptoError.unsupportedEncStringType(encString.type.rawValue)
        }
        guard let iv = encString.iv, let mac = encString.mac else { throw CryptoError.invalidEncString }
        let macKey = SymmetricKey(data: key.macKey)
        let authenticated = iv + encString.ciphertext
        guard HMAC<SHA256>.isValidAuthenticationCode(mac, authenticating: authenticated, using: macKey) else {
            throw CryptoError.macMismatch
        }
        return try aesCBC(.decrypt, data: encString.ciphertext, key: key.encKey, iv: iv)
    }

    // MARK: - Private

    private static func hmac(_ data: Data, key: Data) -> Data {
        let code = HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: key))
        return Data(code)
    }

    private enum Operation { case encrypt, decrypt }

    private static func aesCBC(_ op: Operation, data: Data, key: Data, iv: Data) throws -> Data {
        guard key.count == kCCKeySizeAES256, iv.count == kCCBlockSizeAES128 else {
            throw CryptoError.invalidKeyLength
        }
        let ccOp = (op == .encrypt) ? CCOperation(kCCEncrypt) : CCOperation(kCCDecrypt)
        var out = Data(count: data.count + kCCBlockSizeAES128)
        let outCount = out.count
        var moved = 0
        let status: Int32 = out.withUnsafeMutableBytes { outPtr in
            data.withUnsafeBytesOrEmpty { dataPtr, dataLen in
                iv.withUnsafeBytes { ivPtr in
                    key.withUnsafeBytes { keyPtr in
                        CCCrypt(ccOp,
                                CCAlgorithm(kCCAlgorithmAES),
                                CCOptions(kCCOptionPKCS7Padding),
                                keyPtr.baseAddress, key.count,
                                ivPtr.baseAddress,
                                dataPtr, dataLen,
                                outPtr.baseAddress, outCount,
                                &moved)
                    }
                }
            }
        }
        guard status == kCCSuccess else {
            throw op == .encrypt ? CryptoError.encryptionFailed : CryptoError.decryptionFailed
        }
        return out.prefix(moved)
    }
}

private extension Data {
    func withUnsafeBytesOrEmpty<R>(_ body: (UnsafeRawPointer, Int) -> R) -> R {
        if isEmpty {
            var scratch: UInt8 = 0
            return withUnsafePointer(to: &scratch) { body(UnsafeRawPointer($0), 0) }
        }
        return withUnsafeBytes { body($0.baseAddress!, count) }
    }
}
