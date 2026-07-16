import Foundation
import Observation
import SyncEngine
import VaultRepository

/// Tracks sync state for the unlock/sync pill and the settings screen: last successful sync
/// time, an in-flight flag, the last outcome, and any error. Logic only — no SwiftUI.
@MainActor
@Observable
public final class SyncStatusModel {
    public private(set) var lastSync: Date?
    public private(set) var isSyncing = false
    public private(set) var errorMessage: String?
    /// The result of the most recent successful sync (counts + soft-fail messages), for an
    /// optional "n items, m dropped" status line.
    public private(set) var lastOutcome: SyncOutcome?

    private let vault: VaultService
    private let now: @Sendable () -> Date
    private let onSuccess: @Sendable () async -> Void

    public init(
        vault: VaultService,
        now: @escaping @Sendable () -> Date = { Date() },
        onSuccess: @escaping @Sendable () async -> Void = {}
    ) {
        self.vault = vault
        self.now = now
        self.onSuccess = onSuccess
    }

    /// Run a sync, updating `isSyncing` / `lastSync` / `lastOutcome` / `errorMessage`.
    @discardableResult
    public func sync() async -> Bool {
        guard !isSyncing else { return false }
        isSyncing = true
        errorMessage = nil
        defer { isSyncing = false }
        do {
            let outcome = try await vault.sync()
            lastOutcome = outcome
            lastSync = now()
            await onSuccess()
            return true
        } catch {
            errorMessage = errorString(error)
            // Outbox finalization may have changed local ids/rows before a later pull
            // failed. Reload even on error so the UI never retains stale placeholders.
            await onSuccess()
            return false
        }
    }
}
