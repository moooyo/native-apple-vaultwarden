import Foundation
import UIShared
import VaultRepository

enum MacSSHAgentPolicy: String, CaseIterable, Sendable {
    case always, never, rememberUntilLock
}

struct MacSSHAgentApproval: Sendable {
    let keyName: String
    let peer: MacSSHAgentPeer
}

@MainActor
final class MacSSHAgentRequests {
    struct Backend: Sendable {
        var session: @Sendable () async -> AccountSessionLease?
        var identities: @Sendable (AccountSessionLease) async throws -> [VaultSSHAgentIdentity]
        var signingKey: @Sendable (VaultSSHAgentIdentity, AccountSessionLease) async throws -> String
        var isCurrent: @Sendable (VaultSSHAgentIdentity, AccountSessionLease) async throws -> Bool
        var sign: @Sendable (Data, UInt32, String, String) async throws -> Data
    }

    private struct Context: Equatable {
        let lease: AccountSessionLease
        let policy: MacSSHAgentPolicy
        let generation: UInt64
    }

    private struct ApprovalScope: Hashable {
        let identityID: String
        let revision: String
        let blob: Data
        let peer: MacSSHAgentPeer.Scope
    }

    private let backend: Backend
    private let approve: @MainActor (MacSSHAgentApproval) async -> Bool
    private var lease: AccountSessionLease?
    private var policy = MacSSHAgentPolicy.always
    private var generation: UInt64 = 0
    private var approvals: Set<ApprovalScope> = []
    private var pending: (id: UUID, task: Task<Bool, Never>)?

    init(backend: Backend, approve: @escaping @MainActor (MacSSHAgentApproval) async -> Bool) {
        self.backend = backend
        self.approve = approve
    }

    func configure(lease: AccountSessionLease?, policy: MacSSHAgentPolicy) {
        guard self.lease != lease || self.policy != policy else { return }
        self.lease = lease
        self.policy = policy
        generation &+= 1
        approvals.removeAll()
        pending?.task.cancel()
    }

    func handle(_ request: MacSSHAgentProtocol.Request, peer: MacSSHAgentPeer) async -> MacSSHAgentSocketReply {
        if request == .rejectedBinding {
            return MacSSHAgentSocketReply(packet: MacSSHAgentProtocol.failure, closesConnection: true)
        }
        guard request != .unsupported, let lease else { return .failure }
        let context = Context(lease: lease, policy: policy, generation: generation)
        guard await valid(context) else { return .failure }
        do {
            let identities = try await backend.identities(lease)
            guard await valid(context) else { return .failure }
            switch request {
            case .list:
                var seen: Set<Data> = []
                let entries = identities.compactMap { identity -> (Data, String)? in
                    guard let blob = try? MacSSHSigningKey.publicKeyBlob(publicKey: identity.publicKey),
                          seen.insert(blob).inserted else { return nil }
                    return (blob, MacSSHAgentProtocol.safeLabel(identity.name))
                }
                return MacSSHAgentSocketReply(packet: MacSSHAgentProtocol.identities(entries), validatesOnSend: { [weak self] in
                    await self?.valid(context) == true
                })
            case let .sign(blob, message, flags):
                guard let identity = identities.first(where: { (try? MacSSHSigningKey.publicKeyBlob(publicKey: $0.publicKey)) == blob }) else {
                    return .failure
                }
                var reader = MacSSHKeyReader(blob)
                guard (try reader.name() == "ssh-rsa") == (flags != 0) else { return .failure }
                return try await sign(message, using: identity, blob: blob, flags: flags, peer: peer, context: context)
            case .unsupported, .rejectedBinding:
                return .failure
            }
        } catch {
            return .failure
        }
    }

    private func sign(_ message: Data, using identity: VaultSSHAgentIdentity, blob: Data,
                      flags: UInt32, peer: MacSSHAgentPeer, context: Context) async throws -> MacSSHAgentSocketReply {
        let scope = ApprovalScope(identityID: identity.id, revision: identity.revision, blob: blob, peer: peer.scope)
        let remembering = context.policy == .rememberUntilLock
        let needsPrompt = context.policy == .always || (remembering && !approvals.contains(scope))
        if needsPrompt {
            let request = MacSSHAgentApproval(keyName: MacSSHAgentProtocol.safeLabel(identity.name), peer: peer)
            guard await ask(request) else { return .failure }
        }
        guard await isUsable(identity, context: context) else { return .failure }
        let privateKey = try await backend.signingKey(identity, context.lease)
        guard await valid(context) else { return .failure }
        let signature = try await backend.sign(message, flags, privateKey, identity.publicKey)
        guard await isUsable(identity, context: context) else { return .failure }
        let packet = MacSSHAgentProtocol.signature(signature)
        return MacSSHAgentSocketReply(packet: packet, validatesOnSend: { [weak self] in
            await self?.isUsable(identity, context: context) == true
        }, didSend: remembering && needsPrompt ? { @Sendable [weak self] in
            await self?.remember(scope, context: context)
        } : nil)
    }

    private func ask(_ request: MacSSHAgentApproval) async -> Bool {
        guard pending == nil, !Task.isCancelled else { return false }
        let id = UUID()
        let task = Task { [approve] in await approve(request) }
        pending = (id, task)
        defer { if pending?.id == id { pending = nil } }
        return await withTaskCancellationHandler { await task.value } onCancel: { task.cancel() }
    }

    private func isUsable(_ identity: VaultSSHAgentIdentity, context: Context) async -> Bool {
        guard await valid(context), (try? await backend.isCurrent(identity, context.lease)) == true else { return false }
        return await valid(context)
    }

    private func valid(_ context: Context) async -> Bool {
        guard !Task.isCancelled, generation == context.generation else { return false }
        let current = await backend.session()
        return !Task.isCancelled && generation == context.generation && current == context.lease
    }

    private func remember(_ scope: ApprovalScope, context: Context) async {
        guard await valid(context) else { return }
        if approvals.count >= 128 { approvals.removeAll() }
        approvals.insert(scope)
    }
}

extension MacSSHAgentRequests.Backend {
    init(auth: any AuthService, vault: any VaultService, beforeAccess: @escaping @MainActor () async -> Void) {
        session = {
            await beforeAccess()
            return await auth.transferSession()
        }
        identities = { try await vault.sshAgentIdentities(for: $0) }
        signingKey = { try await vault.sshAgentSigningKey(matching: $0, for: $1) }
        isCurrent = { try await vault.isSSHAgentIdentityCurrent($0, for: $1) }
        sign = { data, flags, privateKey, publicKey in
            let task = Task.detached {
                try Task.checkCancellation()
                return try MacSSHSigningKey.sign(data: data, flags: flags, privateKey: privateKey, publicKey: publicKey)
            }
            return try await withTaskCancellationHandler { try await task.value } onCancel: { task.cancel() }
        }
    }
}
