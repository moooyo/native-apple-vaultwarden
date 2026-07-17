import Foundation

/// Errors surfaced by the app-facing repositories (`AuthRepository`, `VaultRepository`).
///
/// `unsupportedKDF` is the load-bearing PBKDF2-only guard (decision D6): a non-PBKDF2
/// account is rejected with a clear, user-presentable message before any key derivation
/// happens. `network`/`store`/`crypto` wrap the underlying layer errors so callers can
/// branch without importing every dependency's error type.
public enum RepositoryError: Error, Equatable, Sendable {
    /// The account uses a KDF other than PBKDF2 (e.g. Argon2id). PBKDF2-only (D6).
    /// The associated value is the offending KDF type id from prelogin.
    case unsupportedKDF(Int)
    /// The vault is locked — the requested operation needs an unlocked `KeyVault`.
    case locked
    /// Login/unlock failed because the credentials were wrong or the protected key
    /// could not be decrypted.
    case authenticationFailed
    /// No active account / session (e.g. `sync` before `login`).
    case notAuthenticated
    /// The requested cipher does not exist locally.
    case cipherNotFound
    /// The item is protected by an organization key that is not available in the current
    /// key hierarchy. Editing must stop rather than silently dropping or replacing its key.
    case organizationCipherKeyUnavailable
    /// A server token response was missing the protected user key needed to unlock.
    case missingUserKey
    /// A wrapped layer error, carried as a human-readable string so the enum stays
    /// `Equatable`. The `kind` distinguishes which layer produced it.
    case underlying(kind: Kind, description: String)

    public enum Kind: Sendable, Equatable {
        case network
        case store
        case crypto
        case sync
    }

    static func network(_ error: Error) -> RepositoryError {
        .underlying(kind: .network, description: String(describing: error))
    }
    static func store(_ error: Error) -> RepositoryError {
        .underlying(kind: .store, description: String(describing: error))
    }
    static func crypto(_ error: Error) -> RepositoryError {
        .underlying(kind: .crypto, description: String(describing: error))
    }
    static func sync(_ error: Error) -> RepositoryError {
        .underlying(kind: .sync, description: String(describing: error))
    }
}
