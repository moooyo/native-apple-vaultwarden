import Foundation

/// Errors surfaced by `VaultStore`. `prepareFailed`/`stepFailed` carry the SQLite
/// error message for diagnostics (the message is the human-readable string, never
/// secret values — bound parameters are not interpolated into SQL).
public enum VaultStoreError: Error, Equatable, Sendable {
    case openFailed
    case prepareFailed(String)
    case stepFailed(String)
    case notFound
}
