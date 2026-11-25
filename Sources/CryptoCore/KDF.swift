import Foundation

public enum KDF {
    /// Minimum PBKDF2 iterations accepted (matches Bitwarden's PBKDF2_MIN_ITERATIONS).
    public static let minimumPBKDF2Iterations = 5_000
    /// Bitwarden's current recommended iteration count; lower supported values still work.
    public static let recommendedPBKDF2Iterations = 600_000
    /// Bound work requested by untrusted inputs, matching the encrypted import limit.
    public static let maximumPBKDF2Iterations = 2_000_000

    /// Whether a supported account should get an advisory rather than an error.
    public static func isPBKDF2BelowRecommendation(iterations: Int) -> Bool {
        (minimumPBKDF2Iterations..<recommendedPBKDF2Iterations).contains(iterations)
    }

    package static func validatePBKDF2Iterations(_ iterations: Int) throws {
        guard iterations >= minimumPBKDF2Iterations else { throw CryptoError.insufficientKdfParameters }
        guard iterations <= maximumPBKDF2Iterations else { throw CryptoError.excessiveKdfParameters }
    }

    /// Master Key = PBKDF2-HMAC-SHA256(password, salt = trimmed+lowercased email, iterations).
    /// PBKDF2 only — Argon2id is intentionally unsupported.
    public static func deriveMasterKey(password: String, email: String, iterations: Int) throws -> [UInt8] {
        try validatePBKDF2Iterations(iterations)
        let normalized = email.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return try PBKDF2.deriveSHA256(password: Data(password.utf8),
                                       salt: Data(normalized.utf8),
                                       iterations: iterations, keyLength: 32)
    }

    public enum HashPurpose: Int {
        case serverAuthorization = 1   // sent to server (OAuth `password` field)
        case localAuthorization = 2    // persisted for offline unlock verification
    }

    /// base64(PBKDF2-HMAC-SHA256(payload = masterKey, salt = password, iterations = purpose.rawValue)).
    public static func masterPasswordHash(masterKey: [UInt8], password: String, purpose: HashPurpose) throws -> String {
        let out = try PBKDF2.deriveSHA256(password: Data(masterKey),
                                          salt: Data(password.utf8),
                                          iterations: purpose.rawValue, keyLength: 32)
        return Data(out).base64EncodedString()
    }
}
