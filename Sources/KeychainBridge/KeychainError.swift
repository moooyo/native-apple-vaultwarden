import Foundation

/// Errors surfaced by `KeychainBridge` and the underlying Keychain/Secure-Enclave seams.
///
/// `OSStatus`/`LAError` codes from the real `Security`/`LocalAuthentication` impls are
/// mapped onto these cases so callers never have to interpret raw status codes.
public enum KeychainError: Error, Equatable, Sendable {
    /// Biometrics / Secure Enclave unavailable (no hardware, not enrolled, or the
    /// access-controlled key could not be created/used). Also used as the fallback for
    /// the master-password path described in design spec §5.3.
    case unavailable
    /// The user cancelled the biometric prompt, or it failed user verification.
    case userCanceled
    /// The requested item (wrapped key ciphertext, secret, or SE key) does not exist.
    case notFound
    /// An add attempted to create an item that already exists.
    case duplicate
    /// The decrypted user key was not the required 64 bytes (enc 32 || mac 32).
    case invalidUserKey
    /// Any other Keychain failure, carrying the raw `OSStatus` for diagnostics.
    case unexpected(OSStatus)
}
