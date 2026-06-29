import Foundation

/// The result of a `fullSync`. Carries counts plus the non-fatal soft-fail details
/// so the caller (UI / logging) can surface a warning without the sync having thrown.
public struct SyncOutcome: Sendable, Equatable {
    /// Number of ciphers written to the store this sync (new + updated; excludes
    /// rows skipped because the local copy was newer).
    public let upserted: Int
    /// Number of local ciphers deleted because they were absent from the server
    /// (and not pending in the outbox).
    public let deletedLocally: Int
    /// Number of ciphers the server sent that failed to decode (bad/unsupported
    /// EncString, e.g. a type-7 field). Soft-failed: counted, never thrown.
    public let dropped: Int
    /// Human-readable messages for the dropped ciphers (the `droppedCipherErrors`
    /// from the sync response).
    public let droppedMessages: [String]
    /// Number of AutoFill credential identities written (0 if AutoFill is disabled).
    public let identitiesWritten: Int

    public init(upserted: Int, deletedLocally: Int, dropped: Int,
                droppedMessages: [String], identitiesWritten: Int) {
        self.upserted = upserted
        self.deletedLocally = deletedLocally
        self.dropped = dropped
        self.droppedMessages = droppedMessages
        self.identitiesWritten = identitiesWritten
    }
}
