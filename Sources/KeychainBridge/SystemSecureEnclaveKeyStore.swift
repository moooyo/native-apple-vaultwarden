import Foundation

#if canImport(Security)
import Security
#endif
#if canImport(LocalAuthentication)
import LocalAuthentication
#endif

/// Real Secure-Enclave seam. The P-256 private key is generated inside the SE
/// (`kSecAttrTokenIDSecureEnclave`), is non-exportable, and is access-controlled with
/// `.privateKeyUsage + .biometryCurrentSet` so any decryption forces a fresh biometric
/// check and is invalidated when the enrolled biometric set changes.
///
/// ENVIRONMENT NOTE: this type COMPILES on a Command-Line-Tools host (the SDK headers are
/// present) but cannot RUN here — `SecKeyCreateRandomKey` with the SE token and
/// `kSecAttrAccessGroup` require entitlements + signing + a device/simulator. It is
/// exercised only in Xcode. The orchestration is tested via the in-memory fake.
public struct SystemSecureEnclaveKeyStore: SecureEnclaveKeyStore {
    /// ECIES with X9.63 KDF (SHA-256) + AES-GCM, variable-IV — the standard variant whose
    /// ciphertext embeds the ephemeral public key, so wrap (pub only) / unwrap (priv) pair.
    private static let algorithm: SecKeyAlgorithm = .eciesEncryptionStandardVariableIVX963SHA256AESGCM

    public init() {}

    // MARK: - Key lifecycle

    public func createBiometricKey(tag: String, accessGroup: String) throws {
        if hasKey(tag: tag, accessGroup: accessGroup) { return }

        var acError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            &acError
        ) else {
            acError?.release()
            throw KeychainError.unavailable
        }

        let privateKeyAttrs: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: Data(tag.utf8),
            kSecAttrAccessControl as String: access,
            kSecAttrAccessGroup as String: accessGroup,
        ]
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: privateKeyAttrs,
        ]

        var error: Unmanaged<CFError>?
        guard SecKeyCreateRandomKey(attributes as CFDictionary, &error) != nil else {
            error?.release()
            // Key generation failures here are SE-unavailability/entitlement problems.
            throw KeychainError.unavailable
        }
    }

    public func hasKey(tag: String, accessGroup: String) -> Bool {
        let query = baseKeyQuery(tag: tag, accessGroup: accessGroup, returnRef: false)
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess
    }

    public func deleteKey(tag: String, accessGroup: String) {
        var query = baseKeyQuery(tag: tag, accessGroup: accessGroup, returnRef: false)
        query.removeValue(forKey: kSecReturnAttributes as String)
        query.removeValue(forKey: kSecMatchLimit as String)
        SecItemDelete(query as CFDictionary)
    }

    // MARK: - ECIES wrap / unwrap

    public func wrap(_ plaintext: Data, tag: String, accessGroup: String) throws -> Data {
        let privateKey = try fetchPrivateKey(tag: tag, accessGroup: accessGroup, context: nil)
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw KeychainError.unavailable
        }
        guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, Self.algorithm) else {
            throw KeychainError.unavailable
        }
        var error: Unmanaged<CFError>?
        guard let ciphertext = SecKeyCreateEncryptedData(
            publicKey, Self.algorithm, plaintext as CFData, &error
        ) else {
            error?.release()
            throw KeychainError.unavailable
        }
        return ciphertext as Data
    }

    public func unwrap(_ ciphertext: Data, tag: String, accessGroup: String, reason: String) async throws -> Data {
        #if canImport(LocalAuthentication)
        let context = LAContext()
        context.localizedReason = reason
        #else
        let context: AnyObject? = nil
        #endif

        let privateKey: SecKey
        do {
            #if canImport(LocalAuthentication)
            privateKey = try fetchPrivateKey(tag: tag, accessGroup: accessGroup, context: context)
            #else
            privateKey = try fetchPrivateKey(tag: tag, accessGroup: accessGroup, context: nil)
            #endif
        } catch {
            throw error
        }

        guard SecKeyIsAlgorithmSupported(privateKey, .decrypt, Self.algorithm) else {
            throw KeychainError.unavailable
        }

        var error: Unmanaged<CFError>?
        guard let plaintext = SecKeyCreateDecryptedData(
            privateKey, Self.algorithm, ciphertext as CFData, &error
        ) else {
            let mapped = Self.mapSecError(error)
            error?.release()
            throw mapped
        }
        return plaintext as Data
    }

    // MARK: - Private helpers

    private func baseKeyQuery(tag: String, accessGroup: String, returnRef: Bool) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: Data(tag.utf8),
            kSecAttrAccessGroup as String: accessGroup,
        ]
        if returnRef {
            query[kSecReturnRef as String] = true
        } else {
            query[kSecMatchLimit as String] = kSecMatchLimitOne
        }
        return query
    }

    private func fetchPrivateKey(tag: String, accessGroup: String, context: AnyObject?) throws -> SecKey {
        var query = baseKeyQuery(tag: tag, accessGroup: accessGroup, returnRef: true)
        if let context {
            query[kSecUseAuthenticationContext as String] = context
        }
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let item else { throw KeychainError.notFound }
            // SecItemCopyMatching for a key with kSecReturnRef yields a SecKey.
            return item as! SecKey
        case errSecItemNotFound:
            throw KeychainError.notFound
        case errSecUserCanceled:
            throw KeychainError.userCanceled
        default:
            throw KeychainError.unexpected(status)
        }
    }

    /// Maps a `CFError` from `SecKeyCreate{Encrypted,Decrypted}Data` onto `KeychainError`,
    /// translating `LAError` user-cancel/unavailable codes when LocalAuthentication is present.
    private static func mapSecError(_ error: Unmanaged<CFError>?) -> KeychainError {
        guard let cf = error?.takeUnretainedValue() else { return .unavailable }
        let nsError = cf as Error as NSError

        #if canImport(LocalAuthentication)
        if nsError.domain == LAError.errorDomain {
            switch nsError.code {
            case LAError.userCancel.rawValue,
                 LAError.systemCancel.rawValue,
                 LAError.appCancel.rawValue,
                 LAError.authenticationFailed.rawValue:
                return .userCanceled
            case LAError.biometryNotAvailable.rawValue,
                 LAError.biometryNotEnrolled.rawValue,
                 LAError.biometryLockout.rawValue,
                 LAError.passcodeNotSet.rawValue:
                return .unavailable
            default:
                return .unexpected(OSStatus(nsError.code))
            }
        }
        #endif

        // Security-framework errors surface their OSStatus as the NSError code.
        let status = OSStatus(truncatingIfNeeded: nsError.code)
        switch status {
        case errSecUserCanceled:
            return .userCanceled
        case errSecItemNotFound:
            return .notFound
        case errSecAuthFailed:
            return .userCanceled
        default:
            return .unexpected(status)
        }
    }
}
