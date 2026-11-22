import Foundation

public enum PasswordProtectedExportError: Error, Equatable {
    case emptyPassword, unsupportedFormat, unsupportedKDF, unsupportedIterations
    case exceedsSizeLimit, invalidEnvelope, authenticationFailed
}

public enum PasswordProtectedExport {
    private static let fileSizeLimit = 32 * 1_024 * 1_024
    private static let exportIterations = 600_000
    private static let acceptedIterations = KDF.minimumPBKDF2Iterations...2_000_000

    public static func encrypt(_ data: Data, password: String) throws -> Data {
        try validatePassword(password)
        guard data.count <= fileSizeLimit / 4 * 3 else { throw PasswordProtectedExportError.exceedsSizeLimit }
        let salt = try SecureRandom.bytes(16).base64EncodedString()
        let key = try deriveKey(password: password, salt: salt, iterations: exportIterations)
        let validation = Data(UUID().uuidString.lowercased().utf8)
        let envelope = Envelope(encrypted: true, passwordProtected: true, salt: salt,
                                kdfType: 0, kdfIterations: exportIterations,
                                validation: try SymmetricCrypto.encrypt(validation, using: key).stringValue,
                                data: try SymmetricCrypto.encrypt(data, using: key).stringValue)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.withoutEscapingSlashes]
        let encoded = try encoder.encode(envelope)
        guard encoded.count <= fileSizeLimit else { throw PasswordProtectedExportError.exceedsSizeLimit }
        return encoded
    }

    public static func decrypt(_ data: Data, password: String) throws -> Data {
        try validatePassword(password)
        guard data.count <= fileSizeLimit else { throw PasswordProtectedExportError.exceedsSizeLimit }
        guard let envelope = try? JSONDecoder().decode(Envelope.self, from: data) else {
            throw PasswordProtectedExportError.invalidEnvelope
        }
        guard envelope.encrypted, envelope.passwordProtected == true else {
            throw PasswordProtectedExportError.unsupportedFormat
        }
        guard let kdfType = envelope.kdfType, let iterations = envelope.kdfIterations,
              let salt = envelope.salt, salt.utf8.count == 24, Data(base64Encoded: salt)?.count == 16,
              let validation = envelope.validation, validation.utf8.count <= 256,
              let payload = envelope.data else { throw PasswordProtectedExportError.invalidEnvelope }
        guard kdfType == 0 else { throw PasswordProtectedExportError.unsupportedKDF }
        guard acceptedIterations.contains(iterations) else { throw PasswordProtectedExportError.unsupportedIterations }

        let encryptedValidation = try authenticatedField(validation)
        let encryptedPayload = try authenticatedField(payload)
        let key = try deriveKey(password: password, salt: salt, iterations: iterations)
        guard let check = try? SymmetricCrypto.decrypt(encryptedValidation, using: key),
              let text = String(data: check, encoding: .utf8), UUID(uuidString: text) != nil,
              let result = try? SymmetricCrypto.decrypt(encryptedPayload, using: key) else {
            throw PasswordProtectedExportError.authenticationFailed
        }
        return result
    }

    private static func validatePassword(_ password: String) throws {
        guard !password.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw PasswordProtectedExportError.emptyPassword
        }
    }

    private static func deriveKey(password: String, salt: String, iterations: Int) throws -> SymmetricCryptoKey {
        var key = try PBKDF2.deriveSHA256(password: Data(password.utf8), salt: Data(salt.utf8),
                                          iterations: iterations, keyLength: 32)
        defer {
            key.withUnsafeMutableBytes { buffer in
                if let address = buffer.baseAddress { memset_s(address, buffer.count, 0, buffer.count) }
            }
        }
        return KeyStretch.stretchMasterKey(key)
    }

    private static func authenticatedField(_ text: String) throws -> EncString {
        guard text.hasPrefix("2."), let field = try? EncString(parsing: text),
              field.iv?.count == 16, field.mac?.count == 32,
              field.ciphertext.count.isMultiple(of: 16) else { throw PasswordProtectedExportError.invalidEnvelope }
        return field
    }

    private struct Envelope: Codable {
        let encrypted: Bool
        let passwordProtected: Bool?
        let salt: String?
        let kdfType: Int?
        let kdfIterations: Int?
        let validation: String?
        let data: String?

        enum CodingKeys: String, CodingKey {
            case encrypted, passwordProtected, salt, kdfType, kdfIterations, data
            case validation = "encKeyValidation_DO_NOT_EDIT"
        }
    }
}
