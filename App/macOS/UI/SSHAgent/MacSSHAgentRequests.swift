import CryptoKit
import Foundation
import VaultRepository

@MainActor
final class MacSSHAgentRequests {
    struct Access: Equatable, Sendable {
        let lease: AccountSessionLease
        let unlocked: Bool
    }

    struct Backend: Sendable {
        var access: @Sendable () async -> Access?
        var identities: @Sendable (Access) async throws -> [VaultSSHAgentIdentity]
        var signingKey: @Sendable (VaultSSHAgentIdentity, AccountSessionLease) async throws -> String
        var isCurrent: @Sendable (VaultSSHAgentIdentity, AccountSessionLease) async throws -> Bool
        var sign: @Sendable (Data, UInt32, String, String) async throws -> Data
        var refreshIndex: @Sendable (AccountSessionLease) async throws -> Void = { _ in }
        var itemCount: @Sendable (AccountSessionLease) async throws -> Int = { _ in 0 }
    }

    private struct Context: Sendable {
        let lease: AccountSessionLease
        let epoch: UInt64
    }

    private struct ApprovalScope: Hashable, Sendable {
        let app: MacSSHAgentPeer.SigningIdentity
        let fingerprint: String
    }

    private struct Record {
        let identity: VaultSSHAgentIdentity
        let expiry: ContinuousClock.Instant?
    }

    private struct Waiter {
        let id: UUID
        var continuation: CheckedContinuation<Bool, Never>?
    }

    private let backend: Backend
    private let approve: @MainActor (MacSSHAgentApproval) async -> MacSSHApprovalDuration?
    private let complete: @MainActor (UUID, Bool) -> Void
    private let reject: @MainActor () -> Void
    private let now: @MainActor () -> ContinuousClock.Instant
    private let canOperate: @MainActor () -> Bool
    private var lease: AccountSessionLease?
    var defaultDuration = MacSSHApprovalDuration.once
    private var epoch: UInt64 = 0
    private var approvals: [ApprovalScope: Record] = [:]
    private var activeTicket: UUID?
    private var waiting: [Waiter] = []

    init(backend: Backend, approve: @escaping @MainActor (MacSSHAgentApproval) async -> MacSSHApprovalDuration?,
         complete: @escaping @MainActor (UUID, Bool) -> Void = { _, _ in }, reject: @escaping @MainActor () -> Void = {},
         now: @escaping @MainActor () -> ContinuousClock.Instant = { .now }, canOperate: @escaping @MainActor () -> Bool = { true }) {
        self.backend = backend
        self.approve = approve
        self.complete = complete
        self.reject = reject
        self.now = now
        self.canOperate = canOperate
    }

    func configure(lease: AccountSessionLease?) {
        guard self.lease != lease else { return }
        self.lease = lease
        invalidate()
    }

    func invalidate() {
        epoch &+= 1
        approvals.removeAll()
        let cancelled = waiting
        waiting.removeAll()
        for waiter in cancelled { waiter.continuation?.resume(returning: false) }
        reject()
    }

    func handle(_ request: MacSSHAgentProtocol.Request, peer: MacSSHAgentPeer, verifiedHost: String? = nil) async -> MacSSHAgentSocketReply {
        guard let lease else { return .failure }
        let context = Context(lease: lease, epoch: epoch)
        guard canOperate(), !Task.isCancelled else { return .failure }
        switch request {
        case .list:
            return await list(context)
        case let .sign(blob, message, flags):
            var reader = MacSSHKeyReader(blob)
            guard let format = try? reader.name(), (format == "ssh-rsa") == (flags != 0) else { return .failure }
            // Reserve FIFO order before the first await. Unknown keys drop their slot
            // and fail without waiting behind an interactive approval.
            let ticket = UUID()
            waiting.append(Waiter(id: ticket))
            guard let (initialAccess, identity) = await match(blob, context: context) else {
                cancelWaiter(ticket)
                return .failure
            }
            let isQueued = activeTicket != nil || waiting.first?.id != ticket
            guard await takeTurn(ticket, context: context) else {
                cancelWaiter(ticket)
                return .failure
            }
            var releasesOnReturn = true
            defer { if releasesOnReturn { finishTurn(ticket) } }
            let access: Access
            if isQueued {
                guard let (current, matched) = await match(blob, context: context), matched == identity else { return .failure }
                access = current
            } else {
                access = initialAccess
            }
            guard let reply = await sign(message, blob: blob, flags: flags, peer: peer, verifiedHost: verifiedHost,
                                         identity: identity, keyFormat: format, access: access, context: context, ticket: ticket) else { return .failure }
            releasesOnReturn = false
            return reply
        default:
            return .failure
        }
    }

    private func list(_ context: Context) async -> MacSSHAgentSocketReply {
        guard let access = await access(for: context), let identities = try? await backend.identities(access),
              await self.access(for: context) == access else { return .failure }
        var seen: Set<Data> = []
        let entries = identities.compactMap { identity -> (Data, String)? in
            guard let blob = try? MacSSHSigningKey.publicKeyBlob(publicKey: identity.publicKey),
                  seen.insert(blob).inserted else { return nil }
            // Never disclose item names from the locked vault to socket clients.
            return (blob, access.unlocked ? MacSSHAgentProtocol.safeLabel(identity.name) : "")
        }
        return MacSSHAgentSocketReply(packet: MacSSHAgentProtocol.identities(entries), validatesOnSend: { [weak self] in
            await self?.access(for: context) == access
        })
    }

    private func match(_ blob: Data, context: Context) async -> (Access, VaultSSHAgentIdentity)? {
        guard let access = await access(for: context),
              let identities = try? await backend.identities(access),
              let identity = identities.first(where: { (try? MacSSHSigningKey.publicKeyBlob(publicKey: $0.publicKey)) == blob }),
              await self.access(for: context) == access else { return nil }
        return (access, identity)
    }

    private func sign(_ message: Data, blob: Data, flags: UInt32, peer: MacSSHAgentPeer, verifiedHost: String?,
                      identity: VaultSSHAgentIdentity, keyFormat: String, access: Access,
                      context: Context, ticket: UUID) async -> MacSSHAgentSocketReply? {
        guard isCurrent(context) else { return nil }
        var approvalID: UUID?
        var handsOffReceipt = false
        defer { if let approvalID, !handsOffReceipt { complete(approvalID, false) } }
        do {
            let fingerprint = "SHA256:" + Data(SHA256.hash(data: blob)).base64EncodedString().replacingOccurrences(of: "=", with: "")
            let scope = peer.signingIdentity.map { ApprovalScope(app: $0, fingerprint: fingerprint) }
            let useCache = access.unlocked && isRemembered(identity, scope: scope)
            let duration: MacSSHApprovalDuration
            if useCache {
                duration = .once
            } else {
                let request = MacSSHAgentApproval(keyName: MacSSHAgentProtocol.safeLabel(identity.name),
                                                  keyAlgorithm: keyFormat.hasPrefix("ssh-") ? String(keyFormat.dropFirst(4)) : keyFormat,
                                                  fingerprint: fingerprint, verifiedHost: verifiedHost, peer: peer, locked: !access.unlocked,
                                                  lease: context.lease, defaultDuration: defaultDuration)
                approvalID = request.id
                guard let choice = await approve(request) else { return nil }
                duration = scope == nil ? .once : choice
            }
            guard await isUsable(identity, context: context) else { return nil }
            let privateKey = try await backend.signingKey(identity, context.lease)
            guard isCurrent(context) else { return nil }
            let signature = try await backend.sign(message, flags, privateKey, identity.publicKey)
            guard await isUsable(identity, context: context) else { return nil }
            let packet = MacSSHAgentProtocol.signature(signature)
            guard packet != MacSSHAgentProtocol.failure else { return nil }
            let receipt = approvalID
            handsOffReceipt = true
            return MacSSHAgentSocketReply(packet: packet, validatesOnSend: { [weak self] in
                await self?.isUsable(identity, context: context) == true
            }, permitsSignature: { [weak self] in
                guard let self, isCurrent(context) else { return false }
                return !useCache || isRemembered(identity, scope: scope)
            }, didComplete: { [weak self] sent in
                guard let self else { return }
                if let receipt { complete(receipt, sent) }
                if sent, let scope, duration != .once, isCurrent(context) { remember(identity, scope: scope, duration: duration) }
                finishTurn(ticket)
            })
        } catch { return nil }
    }

    private func isCurrent(_ context: Context) -> Bool {
        !Task.isCancelled && epoch == context.epoch && context.lease == lease && canOperate()
    }

    private func access(for context: Context) async -> Access? {
        guard isCurrent(context), let access = await backend.access(), access.lease == context.lease, isCurrent(context) else { return nil }
        return access
    }

    private func isUsable(_ identity: VaultSSHAgentIdentity, context: Context) async -> Bool {
        guard await access(for: context)?.unlocked == true,
              (try? await backend.isCurrent(identity, context.lease)) == true else { return false }
        return await access(for: context)?.unlocked == true
    }

    private func isRemembered(_ identity: VaultSSHAgentIdentity, scope: ApprovalScope?) -> Bool {
        guard let scope, let record = approvals[scope] else { return false }
        guard record.identity == identity, record.expiry.map({ now() < $0 }) != false else {
            approvals.removeValue(forKey: scope)
            return false
        }
        return true
    }

    private func remember(_ identity: VaultSSHAgentIdentity, scope: ApprovalScope, duration: MacSSHApprovalDuration) {
        if approvals.count >= 128 { approvals.removeAll() }
        approvals[scope] = Record(identity: identity, expiry: duration == .minutes15 ? now().advanced(by: .seconds(900)) : nil)
    }

    private func takeTurn(_ ticket: UUID, context: Context) async -> Bool {
        guard isCurrent(context) else { return false }
        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                guard !Task.isCancelled, let index = waiting.firstIndex(where: { $0.id == ticket }) else {
                    continuation.resume(returning: false)
                    return
                }
                waiting[index].continuation = continuation
                advanceQueue()
            }
        } onCancel: { [weak self] in
            Task { @MainActor in self?.cancelWaiter(ticket) }
        }
    }

    private func cancelWaiter(_ id: UUID) {
        guard let index = waiting.firstIndex(where: { $0.id == id }) else { return }
        waiting.remove(at: index).continuation?.resume(returning: false)
        advanceQueue()
    }

    private func finishTurn(_ id: UUID) {
        guard activeTicket == id else { return }
        activeTicket = nil
        advanceQueue()
    }

    private func advanceQueue() {
        guard activeTicket == nil, let ready = waiting.first?.continuation else { return }
        activeTicket = waiting.removeFirst().id
        ready.resume(returning: true)
    }
}

extension MacSSHAgentRequests.Backend {
    init(auth: AuthRepository, vault: VaultRepository, beforeAccess: @escaping @MainActor () async -> Void) {
        access = {
            await beforeAccess()
            guard let lease = await auth.currentSessionLease(), !(await auth.requiresNewLogin()) else { return nil }
            let unlocked = await auth.unlockedSessionLease() == lease
            guard await auth.currentSessionLease() == lease else { return nil }
            return MacSSHAgentRequests.Access(lease: lease, unlocked: unlocked)
        }
        identities = { access in
            if access.unlocked { return try await vault.sshAgentIdentities(for: access.lease) }
            return try await vault.sshAgentPublicIdentities(for: access.lease)
        }
        signingKey = { try await vault.sshAgentSigningKey(matching: $0, for: $1) }
        isCurrent = { try await vault.isSSHAgentIdentityCurrent($0, for: $1) }
        sign = { data, flags, privateKey, publicKey in
            let task = Task.detached {
                try Task.checkCancellation()
                return try MacSSHSigningKey.sign(data: data, flags: flags, privateKey: privateKey, publicKey: publicKey)
            }
            return try await withTaskCancellationHandler { try await task.value } onCancel: { task.cancel() }
        }
        refreshIndex = { try await vault.refreshSSHAgentPublicIndex(for: $0) }
        itemCount = { try await vault.sshAgentItemCount(for: $0) }
    }
}
