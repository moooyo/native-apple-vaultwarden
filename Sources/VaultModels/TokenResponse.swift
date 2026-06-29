import Foundation
import CryptoCore

/// `/identity/connect/token` response. Mixes OAuth snake_case fields
/// (`access_token`, …) with vault PascalCase/camelCase fields (`Key`, `PrivateKey`,
/// `Kdf`, …). The case-insensitive decoder lowercases incoming keys; CodingKeys
/// raw values are the lowercased form of each wire key (underscores are unchanged
/// by lowercasing, so `access_token` stays `access_token`).
public struct TokenResponse: Codable, Sendable {
    public let accessToken: String
    public let expiresIn: Int
    public let refreshToken: String?
    public let tokenType: String
    public let key: EncString?          // protected user key
    public let privateKey: EncString?   // RSA private key (type-2 wrapped)
    public let kdf: Int?
    public let kdfIterations: Int?

    public init(accessToken: String, expiresIn: Int, refreshToken: String?, tokenType: String,
                key: EncString?, privateKey: EncString?, kdf: Int?, kdfIterations: Int?) {
        self.accessToken = accessToken
        self.expiresIn = expiresIn
        self.refreshToken = refreshToken
        self.tokenType = tokenType
        self.key = key
        self.privateKey = privateKey
        self.kdf = kdf
        self.kdfIterations = kdfIterations
    }

    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case expiresIn = "expires_in"
        case refreshToken = "refresh_token"
        case tokenType = "token_type"
        case key
        case privateKey = "privatekey"
        case kdf
        case kdfIterations = "kdfiterations"
    }
}
