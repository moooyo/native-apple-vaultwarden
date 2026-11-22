import Foundation
import Networking
import Observation
import SyncEngine
import VaultRepository

@MainActor @Observable
public final class VaultSyncAccess {
    public private(set) var sendRevision: UInt64 = 0
    public private(set) var backgroundOutboxRevision: UInt64 = 0
    public private(set) var successfulSyncs: UInt64 = 0
    public private(set) var sendCount: Int?
    public private(set) var sendListingDenied = false
    public private(set) var currentScope: AccountSessionLease?
    private let currentSession: @Sendable () async -> AccountSessionLease?
    @ObservationIgnored private var observers: [UUID: (AccountSessionLease, () -> Void)] = [:]

    public init(currentSession: @escaping @Sendable () async -> AccountSessionLease?) {
        self.currentSession = currentSession
    }

    public func session() async -> AccountSessionLease? {
        let scope = await currentSession()
        if scope != currentScope {
            if let previous = currentScope { invalidate(previous) }
            currentScope = scope
            sendCount = nil
            sendListingDenied = false
        }
        return scope
    }

    public func observe(_ scope: AccountSessionLease, onDenied: @escaping @MainActor () -> Void) -> UUID {
        let id = UUID()
        observers[id] = (scope, onDenied)
        return id
    }

    public func removeObserver(_ id: UUID) { observers[id] = nil }

    fileprivate func recordBackgroundOutboxChange(for scope: AccountSessionLease) async {
        guard await session() == scope else { return }
        backgroundOutboxRevision &+= 1
    }

    public func recordSendCount(_ count: Int?, for scope: AccountSessionLease, revision: UInt64) {
        guard scope == currentScope, revision == sendRevision else { return }
        sendCount = count
        if count != nil { sendListingDenied = false }
    }

    public func deny(_ scope: AccountSessionLease) async {
        guard await session() == scope else { return }
        invalidate(scope)
    }

    private func invalidate(_ scope: AccountSessionLease) {
        sendCount = nil
        sendListingDenied = true
        sendRevision &+= 1
        for (owner, notify) in observers.values where owner == scope { notify() }
    }

    public func perform(_ operation: @Sendable (AccountSessionLease) async throws -> SyncOutcome) async throws -> SyncOutcome {
        guard let scope = await session() else { throw RepositoryError.locked }
        let revision = sendRevision
        do {
            let outcome = try await operation(scope)
            guard await session() == scope, revision == sendRevision else { throw CancellationError() }
            successfulSyncs &+= 1
            sendCount = outcome.sendCount
            if outcome.sendCount != nil { sendListingDenied = false }
            return outcome
        } catch {
            if Self.deniesAccess(error) { await deny(scope) }
            else if scope == currentScope, revision == sendRevision { sendCount = nil }
            throw error
        }
    }

    public static func deniesAccess(_ error: Error) -> Bool {
        switch error {
        case RepositoryError.vaultAccessDenied: true
        case let network as NetworkingError: network.deniesVaultListingAccess
        default: false
        }
    }
}

@MainActor public enum VaultLifecycleSync {
    public static func run(access: VaultSyncAccess, drain: () async -> Bool,
                           synchronize: @Sendable (AccountSessionLease) async throws -> SyncOutcome,
                           dataChanged: () -> Void) async -> Bool {
        guard let scope = await access.session() else { return false }
        let imported = await drain()
        do {
            _ = try await access.perform { active in
                guard active == scope else { throw CancellationError() }
                return try await synchronize(active)
            }
            await access.recordBackgroundOutboxChange(for: scope)
            dataChanged()
            return true
        } catch {
            await access.recordBackgroundOutboxChange(for: scope)
            if imported, await access.session() == scope { dataChanged() }
            return false
        }
    }
}
