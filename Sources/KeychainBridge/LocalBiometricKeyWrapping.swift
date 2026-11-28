import CryptoCore
import Foundation

public protocol LocalBiometricKeyWrapping: Sendable {
    func wrap(_ userKey: SymmetricCryptoKey, binding: Data) throws -> Data
    func unwrap(_ envelope: Data, binding: Data, reason: String, fallbackTitle: String) async throws -> SymmetricCryptoKey
}

#if os(macOS)
import CryptoKit
import LocalAuthentication
import Security

public struct SystemLocalBiometricKeyWrapper: LocalBiometricKeyWrapping {
    public init() {}

    public func wrap(_ userKey: SymmetricCryptoKey, binding: Data) throws -> Data {
        let context = LAContext()
        context.interactionNotAllowed = true
        defer { context.invalidate() }
        try Self.requireTouchID(context)
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet], nil
        ) else { throw KeychainError.unavailable }

        var salt = [UInt8](repeating: 0, count: LocalBiometricEnvelope.saltLength)
        guard SecRandomCopyBytes(kSecRandomDefault, salt.count, &salt) == errSecSuccess else {
            throw KeychainError.unavailable
        }

        do {
            let hardwareKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access, authenticationContext: context)
            let ephemeralKey = P256.KeyAgreement.PrivateKey()
            let secret = try ephemeralKey.sharedSecretFromKeyAgreement(with: hardwareKey.publicKey)
            return try LocalBiometricEnvelope.seal(userKey, hardwareKey: hardwareKey.dataRepresentation,
                                                   peerPublicKey: ephemeralKey.publicKey, secret: secret, salt: Data(salt), binding: binding)
        } catch {
            throw Self.mapAuthenticationError(error)
        }
    }

    public func unwrap(_ envelope: Data, binding: Data, reason: String, fallbackTitle: String) async throws -> SymmetricCryptoKey {
        let contents = try LocalBiometricEnvelope(encoded: envelope)
        let request = UnwrapRequest(reason: reason, fallbackTitle: fallbackTitle)
        defer { request.cancel() }
        do {
            return try await withTaskCancellationHandler {
                try Task.checkCancellation()
                let userKey = try await request.open(contents, binding: binding)
                try Task.checkCancellation()
                return userKey
            } onCancel: {
                request.cancel()
            }
        } catch {
            if Task.isCancelled { throw KeychainError.userCanceled }
            throw Self.mapAuthenticationError(error)
        }
    }

    private static func requireTouchID(_ context: LAContext) throws {
        guard SecureEnclave.isAvailable,
              context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil),
              context.biometryType == .touchID else { throw KeychainError.unavailable }
    }

    private static func mapAuthenticationError(_ error: Error) -> KeychainError {
        if let error = error as? KeychainError { return error }
        let error = error as NSError
        if error.domain == LAError.errorDomain {
            switch LAError.Code(rawValue: error.code) {
            case .userFallback:
                return .passwordFallback
            case .appCancel, .systemCancel, .userCancel, .authenticationFailed:
                return .userCanceled
            default:
                return .unavailable
            }
        }
        if error.domain == NSOSStatusErrorDomain {
            switch error.code {
            case Int(errSecUserCanceled), Int(errSecAuthFailed): return .userCanceled
            case Int(errSecItemNotFound): return .notFound
            default: break
            }
        }
        return .unavailable
    }

    private final class UnwrapRequest: @unchecked Sendable {
        private let context = LAContext()
        private let reason: String

        init(reason: String, fallbackTitle: String) {
            self.reason = reason
            context.localizedFallbackTitle = fallbackTitle
            context.touchIDAuthenticationAllowableReuseDuration = 0
        }

        func cancel() { context.invalidate() }

        func open(_ envelope: LocalBiometricEnvelope, binding: Data) async throws -> SymmetricCryptoKey {
            try SystemLocalBiometricKeyWrapper.requireTouchID(context)
            guard try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) else {
                throw KeychainError.userCanceled
            }
            try Task.checkCancellation()
            context.interactionNotAllowed = true
            return try await withCheckedThrowingContinuation { continuation in
                DispatchQueue.global(qos: .userInitiated).async {
                    continuation.resume(with: Result { try self.openWithAuthenticatedContext(envelope, binding: binding) })
                }
            }
        }

        private func openWithAuthenticatedContext(_ envelope: LocalBiometricEnvelope, binding: Data) throws -> SymmetricCryptoKey {
            let hardwareKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: envelope.hardwareKey,
                                                                            authenticationContext: context)
            let secret = try hardwareKey.sharedSecretFromKeyAgreement(with: envelope.peerPublicKey)
            return try envelope.open(secret: secret, binding: binding)
        }
    }
}

package struct LocalBiometricEnvelope: Sendable {
    package static let saltLength = 32
    private static let version: UInt8 = 1
    private static let domain = Data("openvault.local-biometric.p256-hkdf-sha256-aes-gcm.v1".utf8)
    private static let peerKeyLength = 65
    private static let sealedLength = 12 + 64 + 16
    private static let maxHardwareKeyLength = 4096

    package let hardwareKey: Data
    package let peerPublicKey: P256.KeyAgreement.PublicKey
    private let salt: Data
    private let sealedUserKey: Data

    package init(encoded: Data) throws {
        let headerLength = 1 + Self.saltLength + Self.peerKeyLength
        let hardwareKeyLength = encoded.count - headerLength - Self.sealedLength
        guard encoded.first == Self.version, (1...Self.maxHardwareKeyLength).contains(hardwareKeyLength) else {
            throw KeychainError.invalidUserKey
        }
        salt = Data(encoded.dropFirst().prefix(Self.saltLength))
        let peerBytes = encoded.dropFirst(1 + Self.saltLength).prefix(Self.peerKeyLength)
        guard let peer = try? P256.KeyAgreement.PublicKey(x963Representation: peerBytes) else {
            throw KeychainError.invalidUserKey
        }
        peerPublicKey = peer
        hardwareKey = Data(encoded.dropFirst(headerLength).prefix(hardwareKeyLength))
        sealedUserKey = Data(encoded.suffix(Self.sealedLength))
    }

    package static func seal(_ userKey: SymmetricCryptoKey, hardwareKey: Data, peerPublicKey: P256.KeyAgreement.PublicKey,
                             secret: SharedSecret, salt: Data, binding: Data) throws -> Data {
        guard salt.count == saltLength, (1...maxHardwareKeyLength).contains(hardwareKey.count) else {
            throw KeychainError.invalidUserKey
        }
        let header = Self.header(salt: salt, peerPublicKey: peerPublicKey, hardwareKey: hardwareKey)
        let context = Self.authenticatedData(header: header, hardwareKeyLength: hardwareKey.count, binding: binding)
        let key = Self.wrappingKey(secret: secret, salt: salt)
        let sealed = try AES.GCM.seal(userKey.encKey + userKey.macKey, using: key, authenticating: context)
        guard let combined = sealed.combined, combined.count == sealedLength else { throw KeychainError.invalidUserKey }
        return header + combined
    }

    package func open(secret: SharedSecret, binding: Data) throws -> SymmetricCryptoKey {
        let header = Self.header(salt: salt, peerPublicKey: peerPublicKey, hardwareKey: hardwareKey)
        let context = Self.authenticatedData(header: header, hardwareKeyLength: hardwareKey.count, binding: binding)
        do {
            let ciphertext = try AES.GCM.SealedBox(combined: sealedUserKey)
            let plaintext = try AES.GCM.open(ciphertext, using: Self.wrappingKey(secret: secret, salt: salt), authenticating: context)
            return try SymmetricCryptoKey(combined: plaintext)
        } catch {
            throw KeychainError.invalidUserKey
        }
    }

    private static func header(salt: Data, peerPublicKey: P256.KeyAgreement.PublicKey, hardwareKey: Data) -> Data {
        Data([version]) + salt + peerPublicKey.x963Representation + hardwareKey
    }

    private static func authenticatedData(header: Data, hardwareKeyLength: Int, binding: Data) -> Data {
        let length = UInt16(hardwareKeyLength).bigEndian
        return withUnsafeBytes(of: length) { domain + Data($0) + header + binding }
    }

    private static func wrappingKey(secret: SharedSecret, salt: Data) -> SymmetricKey {
        secret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: domain, outputByteCount: 32)
    }
}
#endif
