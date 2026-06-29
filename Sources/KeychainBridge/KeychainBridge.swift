import Foundation
import CryptoCore

/// The ONLY cross-process key channel (design spec §5.3): the 64-byte UserKey is wrapped
/// by a Secure-Enclave key gated behind biometrics and the ciphertext is stored in a
/// shared Keychain access group, so the main app and the AutoFill extension can both
/// recover it with Face ID / Touch ID / Optic ID without the master password. The
/// plaintext UserKey NEVER crosses process boundaries — only the SE-wrapped ciphertext.
///
/// Orchestration is split across two injectable seams (`SecureEnclaveKeyStore` +
/// `KeychainItemStore`) so the logic here is fully unit-testable with in-memory fakes,
/// while the real `Security`/`LocalAuthentication` implementations run only in a signed
/// app on device/simulator.
public actor KeychainBridge {
    private let secureEnclave: SecureEnclaveKeyStore
    private let itemStore: KeychainItemStore
    private let accessGroup: String
    private let service: String

    /// Account name (within the access group) under which the SE-wrapped UserKey lives.
    private var wrappedKeyAccount: String { "\(service).biometric-userkey" }
    /// Application tag for the SE private key.
    private var seKeyTag: String { "\(service).biometric-sekey" }

    /// - Parameters:
    ///   - accessGroup: shared Keychain access group (e.g. `<TEAMID>.dev.moooyo.tessera.shared`).
    ///   - service: namespacing prefix for this bridge's items (e.g. the bundle id).
    ///   - secureEnclave: SE key seam; defaults to the real system implementation.
    ///   - itemStore: generic-password seam; defaults to the real system implementation.
    public init(accessGroup: String,
                service: String,
                secureEnclave: SecureEnclaveKeyStore = SystemSecureEnclaveKeyStore(),
                itemStore: KeychainItemStore = SystemKeychainItemStore()) {
        self.accessGroup = accessGroup
        self.service = service
        self.secureEnclave = secureEnclave
        self.itemStore = itemStore
    }

    // MARK: - Biometric unlock

    /// Enables biometric unlock: generate the SE key (once), ECIES-wrap the 64-byte
    /// UserKey, and store the ciphertext in the shared access group. Call this after a
    /// successful master-password unlock.
    public func enableBiometricUnlock(userKey: SymmetricCryptoKey) throws {
        let combined = userKey.encKey + userKey.macKey
        // Defensive: SymmetricCryptoKey guarantees 32+32, but the wire contract is 64.
        guard combined.count == 64 else { throw KeychainError.invalidUserKey }

        if !secureEnclave.hasKey(tag: seKeyTag, accessGroup: accessGroup) {
            try secureEnclave.createBiometricKey(tag: seKeyTag, accessGroup: accessGroup)
        }
        let ciphertext = try secureEnclave.wrap(combined, tag: seKeyTag, accessGroup: accessGroup)
        // The ciphertext itself need not be biometry-gated — the SE key already is.
        try itemStore.set(ciphertext, account: wrappedKeyAccount, accessGroup: accessGroup, biometryGated: false)
    }

    /// Prompts biometrics and returns the unwrapped UserKey.
    ///
    /// - Throws: `.notFound` if biometric unlock was never enabled; `.invalidUserKey` if
    ///   the unwrapped payload is not exactly 64 bytes; `.userCanceled`/`.unavailable`
    ///   from the biometric prompt.
    public func unlockWithBiometrics(reason: String) async throws -> SymmetricCryptoKey {
        guard let ciphertext = try await itemStore.get(account: wrappedKeyAccount, accessGroup: accessGroup) else {
            throw KeychainError.notFound
        }
        let combined = try await secureEnclave.unwrap(ciphertext, tag: seKeyTag, accessGroup: accessGroup, reason: reason)
        guard combined.count == 64 else { throw KeychainError.invalidUserKey }
        do {
            return try SymmetricCryptoKey(combined: combined)
        } catch {
            throw KeychainError.invalidUserKey
        }
    }

    /// Whether biometric unlock is currently enabled (SE key present AND ciphertext stored).
    public func isBiometricUnlockEnabled() async -> Bool {
        guard secureEnclave.hasKey(tag: seKeyTag, accessGroup: accessGroup) else { return false }
        let ciphertext = try? await itemStore.get(account: wrappedKeyAccount, accessGroup: accessGroup)
        return (ciphertext ?? nil) != nil
    }

    /// Disables biometric unlock: removes both the wrapped-key ciphertext and the SE key.
    public func disableBiometricUnlock() {
        itemStore.delete(account: wrappedKeyAccount, accessGroup: accessGroup)
        secureEnclave.deleteKey(tag: seKeyTag, accessGroup: accessGroup)
    }

    // MARK: - Plain shared-access-group secrets
    // For the refresh token, the offline local-auth hash, and the DB passphrase.

    /// Stores `data` for `account` in the shared access group, replacing any existing value.
    /// `biometryGated` requests biometric gating on the item itself.
    public func setSecret(_ data: Data, account: String, biometryGated: Bool) throws {
        try itemStore.set(data, account: account, accessGroup: accessGroup, biometryGated: biometryGated)
    }

    /// Returns the secret stored for `account`, or `nil` if absent.
    public func getSecret(account: String) async throws -> Data? {
        try await itemStore.get(account: account, accessGroup: accessGroup)
    }

    /// Deletes the secret stored for `account` (best effort).
    public func deleteSecret(account: String) {
        itemStore.delete(account: account, accessGroup: accessGroup)
    }
}
