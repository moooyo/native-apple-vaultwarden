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
    public private(set) var syncAttempt: UInt64 = 0
    public private(set) var errorMessage: String?
    /// The result of the most recent successful sync (counts + soft-fail messages), for an
    /// optional "n items, m dropped" status line.
    public private(set) var lastOutcome: SyncOutcome?
    public private(set) var outboxStatus = VaultOutboxStatus()
    public private(set) var isResolving = false
    public private(set) var resolutionError: String?
    public private(set) var isOutboxStatusUnavailable = false

    public var hasOutstandingChanges: Bool { outboxStatus.pendingCount > 0 || !outboxStatus.issues.isEmpty }

    private let vault: VaultService
    public let syncAccess: VaultSyncAccess?
    private let now: @Sendable () -> Date
    private let onSuccess: @Sendable () async -> Void
    private var outboxRequest: UInt64 = 0
    private var outboxScope: AccountSessionLease?

    public func accountDisplayName(email: String?, serverURL: String) -> String? {
        guard let email, let profile = lastOutcome?.profile,
              profile.email.caseInsensitiveCompare(email) == .orderedSame,
              let profileServer = profile.serverURL,
              profileServer.trimmingCharacters(in: CharacterSet(charactersIn: "/")) ==
                serverURL.trimmingCharacters(in: CharacterSet(charactersIn: "/")),
              let name = profile.name?.trimmingCharacters(in: .whitespacesAndNewlines), !name.isEmpty else {
            return nil
        }
        return name
    }

    public var statusDescription: String {
        if isSyncing { return "正在同步…" }
        if isResolving { return "正在处理同步问题…" }
        if !outboxStatus.issues.isEmpty { return "有同步问题需要处理" }
        if let errorMessage { return errorMessage }
        if outboxStatus.pendingCount > 0 { return "有更改待上传" }
        if isOutboxStatusUnavailable { return "无法确认同步状态" }
        if let lastSync { return "已同步 · \(lastSync.formatted(.relative(presentation: .named)))" }
        return "尚未同步"
    }

    public init(
        vault: VaultService,
        syncAccess: VaultSyncAccess? = nil,
        now: @escaping @Sendable () -> Date = { Date() },
        onSuccess: @escaping @Sendable () async -> Void = {}
    ) {
        self.vault = vault
        self.syncAccess = syncAccess ?? vault.syncAccess
        self.now = now
        self.onSuccess = onSuccess
    }

    public func refreshOutbox() async {
        outboxRequest &+= 1
        let request = outboxRequest
        let scope = await syncAccess?.session()
        guard request == outboxRequest, !Task.isCancelled else { return }
        if scope != outboxScope {
            outboxScope = scope
            outboxStatus = VaultOutboxStatus()
            resolutionError = nil
        }
        guard syncAccess == nil || scope != nil else {
            outboxStatus = VaultOutboxStatus()
            isOutboxStatusUnavailable = true
            return
        }
        let result = try? await vault.outboxStatus(for: scope)
        let current = await syncAccess?.session()
        guard request == outboxRequest, !Task.isCancelled else { return }
        guard current == scope else {
            outboxScope = current
            outboxStatus = VaultOutboxStatus()
            resolutionError = nil
            isOutboxStatusUnavailable = true
            return
        }
        if let result { outboxStatus = result }
        isOutboxStatusUnavailable = result == nil
    }

    @discardableResult
    public func resolve(_ issue: VaultOutboxIssue, action: VaultOutboxAction) async -> Bool {
        guard !isSyncing, !isResolving else { return false }
        guard outboxStatus.issues.contains(issue) else {
            resolutionError = errorString(RepositoryError.outboxIssueChanged)
            return false
        }
        isResolving = true
        resolutionError = nil
        defer { isResolving = false }
        let scope = await syncAccess?.session()
        guard syncAccess == nil || scope != nil && scope == outboxScope else {
            await refreshOutbox()
            return false
        }
        do {
            try await vault.resolveOutboxIssue(issue, action: action, for: scope)
            guard await syncAccess?.session() == scope else { await refreshOutbox(); return false }
            await refreshOutbox()
            await onSuccess()
            return true
        } catch {
            if let scope, VaultSyncAccess.deniesAccess(error) { await syncAccess?.deny(scope) }
            let isCurrent = await syncAccess?.session() == scope
            await refreshOutbox()
            if isCurrent && !Task.isCancelled { resolutionError = errorString(error) }
            return false
        }
    }

    /// Run a sync, updating `isSyncing` / `lastSync` / `lastOutcome` / `errorMessage`.
    @discardableResult
    public func sync() async -> Bool {
        guard !isSyncing, !isResolving else { return false }
        syncAttempt &+= 1
        isSyncing = true
        errorMessage = nil
        resolutionError = nil
        defer { isSyncing = false }
        do {
            let outcome = try await vault.synchronize(access: syncAccess)
            lastOutcome = outcome
            lastSync = now()
            await refreshOutbox()
            await onSuccess()
            return true
        } catch {
            errorMessage = errorString(error)
            await refreshOutbox()
            // Outbox finalization may have changed local ids/rows before a later pull
            // failed. Reload even on error so the UI never retains stale placeholders.
            await onSuccess()
            return false
        }
    }
}
