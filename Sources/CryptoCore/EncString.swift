import Foundation

public struct EncString: Equatable, Sendable {
    public let type: EncryptionType
    public let iv: Data?
    public let ciphertext: Data
    public let mac: Data?

    public init(type: EncryptionType, iv: Data?, ciphertext: Data, mac: Data?) {
        self.type = type
        self.iv = iv
        self.ciphertext = ciphertext
        self.mac = mac
    }

    public init(parsing string: String) throws {
        guard let dot = string.firstIndex(of: ".") else { throw CryptoError.invalidEncString }
        guard let rawType = Int(string[string.startIndex..<dot]),
              let type = EncryptionType(rawValue: rawType) else { throw CryptoError.invalidEncString }
        let body = String(string[string.index(after: dot)...])
        let parts = body.split(separator: "|", omittingEmptySubsequences: false).map(String.init)

        func b64(_ s: String) throws -> Data {
            guard let d = Data(base64Encoded: s) else { throw CryptoError.invalidEncString }
            return d
        }

        switch type {
        case .aesCbc256_B64: // iv|ct, no mac
            guard parts.count == 2 else { throw CryptoError.invalidEncString }
            self.init(type: type, iv: try b64(parts[0]), ciphertext: try b64(parts[1]), mac: nil)
        case .aesCbc128_HmacSha256_B64, .aesCbc256_HmacSha256_B64: // iv|ct|mac
            guard parts.count == 3 else { throw CryptoError.invalidEncString }
            self.init(type: type, iv: try b64(parts[0]), ciphertext: try b64(parts[1]), mac: try b64(parts[2]))
        case .rsa2048_OaepSha256_B64, .rsa2048_OaepSha1_B64, .coseEncrypt0_B64: // single part
            guard parts.count == 1 else { throw CryptoError.invalidEncString }
            self.init(type: type, iv: nil, ciphertext: try b64(parts[0]), mac: nil)
        case .rsa2048_OaepSha256_HmacSha256_B64, .rsa2048_OaepSha1_HmacSha256_B64: // data|mac
            guard parts.count == 2 else { throw CryptoError.invalidEncString }
            self.init(type: type, iv: nil, ciphertext: try b64(parts[0]), mac: try b64(parts[1]))
        }
    }

    public var stringValue: String {
        let b = ciphertext.base64EncodedString()
        switch type {
        case .aesCbc256_B64:
            return "\(type.rawValue).\(iv?.base64EncodedString() ?? "")|\(b)"
        case .aesCbc128_HmacSha256_B64, .aesCbc256_HmacSha256_B64:
            return "\(type.rawValue).\(iv?.base64EncodedString() ?? "")|\(b)|\(mac?.base64EncodedString() ?? "")"
        case .rsa2048_OaepSha256_B64, .rsa2048_OaepSha1_B64, .coseEncrypt0_B64:
            return "\(type.rawValue).\(b)"
        case .rsa2048_OaepSha256_HmacSha256_B64, .rsa2048_OaepSha1_HmacSha256_B64:
            return "\(type.rawValue).\(b)|\(mac?.base64EncodedString() ?? "")"
        }
    }
}
