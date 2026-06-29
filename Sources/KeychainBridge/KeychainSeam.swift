import Foundation

/// Wraps Secure-Enclave key generation + ECIES wrap/unwrap behind a protocol so the
/// `KeychainBridge` orchestration is unit-testable with an in-memory fake.
///
/// The real implementation (`SystemSecureEnclaveKeyStore`) keeps the private key inside
/// the Secure Enclave and only ever exposes the public key for wrapping; unwrapping the
/// user key forces a biometric prompt because the SE key is access-controlled. None of
/// these operations can run on a Command-Line-Tools host (they need entitlements +
/// signing + the SE token), so the protocol exists to keep the logic testable while the
/// real impl still compiles.
public protocol SecureEnclaveKeyStore: Sendable {
    /// Creates the biometric-gated SE P-256 key for `tag`/`accessGroup` if it does not
    /// already exist. Idempotent: a no-op when the key is present.
    func createBiometricKey(tag: String, accessGroup: String) throws

    /// Whether an SE key exists for `tag`/`accessGroup`.
    func hasKey(tag: String, accessGroup: String) -> Bool

    /// Deletes the SE key for `tag`/`accessGroup` (best effort).
    func deleteKey(tag: String, accessGroup: String)

    /// ECIES-encrypts `plaintext` with the SE public key. Does NOT require biometrics.
    func wrap(_ plaintext: Data, tag: String, accessGroup: String) throws -> Data

    /// ECIES-decrypts `ciphertext` with the SE private key. Triggers the biometric prompt
    /// (`reason` is the localized reason shown to the user).
    func unwrap(_ ciphertext: Data, tag: String, accessGroup: String, reason: String) async throws -> Data
}

/// Wraps generic-password `SecItem` CRUD behind a protocol so the orchestration is
/// unit-testable with an in-memory fake. The real implementation
/// (`SystemKeychainItemStore`) stores items in a shared access group so both the main app
/// and the AutoFill extension can read them.
public protocol KeychainItemStore: Sendable {
    /// Stores `data` for `account`/`accessGroup`, replacing any existing value.
    /// `biometryGated` requests `.userPresence` access control on the item itself
    /// (used for secrets the design spec keeps behind biometrics, not the SE-wrapped key).
    func set(_ data: Data, account: String, accessGroup: String, biometryGated: Bool) throws

    /// Returns the stored value for `account`/`accessGroup`, or `nil` if absent.
    /// `async` because a biometry-gated item may prompt the user on read.
    func get(account: String, accessGroup: String) async throws -> Data?

    /// Deletes the value for `account`/`accessGroup` (best effort).
    func delete(account: String, accessGroup: String)
}
