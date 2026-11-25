import CryptoCore
import Foundation
import KeyVault
import Networking

package struct DeviceLoginGrant: Sendable {
    let requestID: UUID
    let accessCode: DeviceLoginAccessCode
    let userKey: SymmetricCryptoKey
    let expiresAt: ContinuousClock.Instant

    func checkExpiry() throws {
        guard .now < expiresAt else { throw DeviceLoginError.requestUnavailable }
    }
}

public actor DeviceApprovalRepository {
    public struct PendingSignIn: Identifiable, Sendable {
        public let id: UUID
        public let fingerprint: String
    }

    public struct Approval: Identifiable, Sendable {
        public var id: UUID { request.id }
        public let request: DeviceLoginRequest
        public let fingerprint: String
        fileprivate let lease: AccountSessionLease
        fileprivate let email: String
    }

    private struct Attempt: Sendable {
        let request: DeviceLoginRequest
        let email: String
        let server: ServerEnvironment
        let code: DeviceLoginAccessCode
        let key: DeviceLoginKey
        let expiresAt: ContinuousClock.Instant
    }

    private let api: APIClient
    private let auth: AuthRepository
    private let keyVault: KeyVault
    private let words: [String]
    private var generation: UInt64 = 0
    private var attempt: Attempt?
    private var expiry: Task<Void, Never>?

    public init(api: APIClient, auth: AuthRepository, keyVault: KeyVault, fingerprintWords: [String]) {
        self.api = api
        self.auth = auth
        self.keyVault = keyVault
        self.words = fingerprintWords
    }

    deinit { expiry?.cancel() }

    public func begin(email input: String, serverURL: String) async throws -> PendingSignIn {
        cancel()
        let generation = generation
        let email = try DeviceLoginWire.normalizedEmail(input)
        guard let server = ServerEnvironment(string: serverURL), server.base.scheme == "https", api.allowsServer(server),
              try await api.isKnownDeviceForLogin(email: email, server: server) else { throw DeviceLoginError.requestUnavailable }
        try check(generation)
        let key = try DeviceLoginKey()
        let code = try DeviceLoginAccessCode.generate()
        let fingerprint = try key.fingerprint(email: email, words: words)
        // Leave a small margin for the request transit and server-side expiration.
        let deadline = ContinuousClock.now + .seconds(295)
        let request = try await api.createDeviceLoginRequest(email: email, accessCode: code, publicKey: key.publicKey, server: server)
        try check(generation)
        guard .now < deadline else { throw DeviceLoginError.requestUnavailable }
        attempt = Attempt(request: request, email: email, server: server, code: code, key: key, expiresAt: deadline)
        expiry = Task { [weak self] in
            do { try await ContinuousClock().sleep(until: deadline) } catch { return }
            await self?.expire(generation)
        }
        return PendingSignIn(id: request.id, fingerprint: fingerprint)
    }

    public func checkApproval(requestID: UUID) async throws -> LoginResult? {
        let generation = generation
        guard let attempt, attempt.request.id == requestID, .now < attempt.expiresAt else { throw DeviceLoginError.requestUnavailable }
        let response = try await api.pollDeviceLoginRequest(id: requestID, accessCode: attempt.code, server: attempt.server)
        try check(generation)
        guard .now < attempt.expiresAt, response.publicKey == attempt.key.publicKey,
              response.masterPasswordHash == nil else { cancel(); throw DeviceLoginError.invalidResponse }
        if response.isPending { return nil }
        guard response.requestApproved == true, let protectedKey = response.key else { cancel(); throw DeviceLoginError.requestUnavailable }
        let key = try attempt.key.unwrap(protectedKey)
        let grant = DeviceLoginGrant(requestID: requestID, accessCode: attempt.code, userKey: key, expiresAt: attempt.expiresAt)
        // The server grant is one-use; don't resubmit after an uncertain response.
        cancel()
        return try await auth.acceptDeviceLogin(email: attempt.email, server: attempt.server, grant: grant)
    }

    public func cancel(requestID: UUID? = nil) {
        guard requestID == nil || attempt?.request.id == requestID else { return }
        generation &+= 1
        expiry?.cancel()
        expiry = nil
        attempt?.key.invalidate()
        attempt = nil
    }

    private func expire(_ expected: UInt64) {
        if generation == expected { cancel() }
    }

    private func check(_ expected: UInt64) throws {
        try Task.checkCancellation()
        guard generation == expected else { throw DeviceLoginError.requestUnavailable }
    }

    public func unlockedSessionLease() async -> AccountSessionLease? { await auth.unlockedSessionLease() }

    public func approvalRequests(for lease: AccountSessionLease) async throws -> [Approval] {
        let context = try await auth.accountActionContext(for: lease)
        guard let session = await auth.session, session.accountID == lease.accountID else { throw RepositoryError.locked }
        let requests = try await api.pendingDeviceLoginRequests(accountID: lease.accountID, contextID: context)
        guard await auth.unlockedSessionLease() == lease else { throw RepositoryError.locked }
        return try requests.filter { $0.isPending && $0.creationDate.addingTimeInterval(300) > .now }.map {
            Approval(request: $0, fingerprint: try DeviceLoginKey.fingerprint(email: session.email, publicKey: $0.publicKey, words: words),
                     lease: lease, email: session.email)
        }
    }

    public func respond(to approval: Approval, approve: Bool, password: String) async throws {
        let lease = approval.lease
        try await auth.verifyMasterPassword(password, for: lease)
        let context = try await auth.accountActionContext(for: lease)
        let request = try await api.deviceLoginRequest(id: approval.id, accountID: lease.accountID, contextID: context)
        guard request.isPending, request.creationDate.addingTimeInterval(300) > .now,
              request.publicKey == approval.request.publicKey, await auth.unlockedSessionLease() == lease else {
            throw DeviceLoginError.requestUnavailable
        }
        let decision: DeviceLoginDecision
        if approve {
            let key = try await keyVault.userKeyForBiometricEnrollment()
            defer { key.erase() }
            decision = .approve(try DeviceLoginKey.wrap(key, publicKey: request.publicKey))
        } else { decision = .deny }
        guard await auth.unlockedSessionLease() == lease else { throw RepositoryError.locked }
        try Task.checkCancellation()
        _ = try await api.respondToDeviceLoginRequest(id: request.id, accountID: lease.accountID, contextID: context, decision: decision)
        guard await auth.unlockedSessionLease() == lease else { throw RepositoryError.locked }
    }
}
