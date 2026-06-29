import Foundation

/// Errors thrown by `SyncEngine` for conditions that genuinely abort an operation.
///
/// Note: soft-failures (bad ciphers dropped by the server response, outbox conflicts)
/// do NOT throw — they are surfaced in `SyncOutcome` / `flushOutbox`'s conflict
/// accounting. Only hard failures (a missing profile, an outbox payload that can't be
/// decoded) end up here.
public enum SyncError: Error, Equatable, Sendable {
    /// The locked vault rejected a decryption needed to build the search index /
    /// identities. Sync cannot proceed without an unlocked `KeyVault`.
    case vaultLocked
    /// An outbox row's `payload_json` could not be decoded into a request DTO.
    case malformedOutboxPayload(id: Int64?)
    /// An outbox row carried an unrecognized `op_type`.
    case unknownOutboxOp(String)
}
