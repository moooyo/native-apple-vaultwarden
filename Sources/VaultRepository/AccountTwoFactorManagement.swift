import Foundation
import Networking

public enum AccountTwoFactorError: Error, Sendable, Equatable {
    case busy
    case invalidCode
    case invalidEmail
    case invalidKeyName
    case securityKeyLimit
    case setupExpired
    case configurationChanged
    case unsupportedServer
    case serverRejected
    case requestFailed
    case changeUnconfirmed
}

public struct AccountAuthenticatorSetup: Sendable {
    public let secret: String
    fileprivate let verificationToken: String
    fileprivate let stamp: AccountTwoFactorSetupStamp
}

public struct AccountEmailTwoFactorSetup: Sendable {
    public let address: String
    fileprivate let stamp: AccountTwoFactorSetupStamp
}

fileprivate struct AccountTwoFactorSetupStamp: Sendable {
    let id: UUID
    let lease: AccountSessionLease
    let expiresAt: ContinuousClock.Instant
}

/// Online account security settings. Setup grants belong to one unlocked vault incarnation.
/// Passwords, verification tokens, authenticator secrets and recovery codes are not persisted.
public actor AccountTwoFactorManagement {
    private let api: APIClient
    private let auth: AuthRepository
    private var isBusy = false
    private var currentSetupID: UUID?

    public init(api: APIClient, auth: AuthRepository) {
        self.api = api
        self.auth = auth
    }

    public func unlockedSessionLease() async -> AccountSessionLease? {
        await auth.unlockedSessionLease()
    }

    public func securityKeyRegistrationEnvironment(for lease: AccountSessionLease) async throws -> ServerEnvironment {
        try await securityKeyRegistrationAccount(for: lease).environment
    }

    public func methods(for lease: AccountSessionLease) async throws -> [TwoFactorMethodStatus] {
        try await request(for: lease) { try await self.api.listTwoFactorMethods($0) }
    }

    public func beginAuthenticatorSetup(for lease: AccountSessionLease, password: String) async throws
        -> AccountAuthenticatorSetup {
        try await exclusively {
            let proof = try await self.passwordProof(for: lease, password: password)
            let stamp = await self.newSetup(for: lease)
            let verified = try await self.request(for: lease) {
                try await self.api.getTwoFactorAuthenticator($0, proof: proof)
            }
            guard !verified.enabled else { throw AccountTwoFactorError.configurationChanged }
            return AccountAuthenticatorSetup(secret: verified.key, verificationToken: verified.userVerificationToken, stamp: stamp)
        }
    }

    public func enableAuthenticator(_ setup: AccountAuthenticatorSetup, code: String, password: String,
                                    for lease: AccountSessionLease) async throws {
        guard Self.isLoginCode(code) else { throw AccountTwoFactorError.invalidCode }
        try await exclusively {
            try await self.checkSetup(setup.stamp, for: lease)
            // Vaultwarden signs the setup secret into the verification token. A fresh
            // get-authenticator before enabling would generate a different secret.
            let proof = try await self.passwordProof(for: lease, password: password)
            let methods = try await self.methods(for: lease)
            guard !methods.contains(where: { $0.provider == .authenticator && $0.enabled }) else {
                throw AccountTwoFactorError.configurationChanged
            }
            try await self.checkSetup(setup.stamp, for: lease)
            try await self.changeSetup(for: lease) {
                try await self.api.enableTwoFactorAuthenticator($0, key: setup.secret, code: code,
                                                                 verificationToken: setup.verificationToken)
            }
            // The mutation response echoes the submitted key. Read back the stored key.
            try await self.confirmChange(for: lease) {
                let result = try await self.request(for: lease) { try await self.api.getTwoFactorAuthenticator($0, proof: proof) }
                guard result.enabled, result.key == setup.secret else { throw AccountTwoFactorError.changeUnconfirmed }
            }
        }
    }

    public func removeAuthenticator(for lease: AccountSessionLease, password: String) async throws {
        try await exclusively {
            let proof = try await self.passwordProof(for: lease, password: password)
            let verified = try await self.request(for: lease) {
                try await self.api.getTwoFactorAuthenticator($0, proof: proof)
            }
            guard verified.enabled else { throw AccountTwoFactorError.configurationChanged }
            try await self.removeMethod(.authenticator, for: lease) {
                try await self.api.removeTwoFactorAuthenticator($0, verified: verified)
            }
        }
    }

    public func beginEmailSetup(address: String, for lease: AccountSessionLease, password: String) async throws
        -> AccountEmailTwoFactorSetup {
        let address = try Self.validateEmailAddress(address)
        return try await exclusively {
            let proof = try await self.passwordProof(for: lease, password: password)
            let verified = try await self.request(for: lease) { try await self.api.getTwoFactorEmail($0, proof: proof) }
            // The send route replaces an existing configuration. Call it only for a
            // freshly verified disabled provider, never as a way to change an address.
            guard !verified.enabled else { throw AccountTwoFactorError.configurationChanged }
            let stamp = await self.newSetup(for: lease)
            try await self.request(for: lease, changing: true) { try await self.api.sendTwoFactorSetupEmail($0, address: address, verified: verified) }
            return AccountEmailTwoFactorSetup(address: address, stamp: stamp)
        }
    }

    public func enableEmail(_ setup: AccountEmailTwoFactorSetup, code: String, password: String,
                            for lease: AccountSessionLease) async throws {
        // Native login accepts six-digit email codes. Do not enroll a provider that
        // this client would not subsequently be able to use at sign-in.
        guard Self.isLoginCode(code) else { throw AccountTwoFactorError.invalidCode }
        try await exclusively {
            try await self.checkSetup(setup.stamp, for: lease)
            let proof = try await self.passwordProof(for: lease, password: password)
            let verified = try await self.request(for: lease) { try await self.api.getTwoFactorEmail($0, proof: proof) }
            guard !verified.enabled else { throw AccountTwoFactorError.configurationChanged }
            try await self.checkSetup(setup.stamp, for: lease)
            try await self.changeSetup(for: lease) {
                try await self.api.enableTwoFactorEmail($0, address: setup.address, code: code, verified: verified)
            }
            // Vaultwarden promotes the server's pending challenge. Confirm it was for
            // the intended address before reporting that this setup succeeded.
            try await self.confirmChange(for: lease) {
                let result = try await self.request(for: lease) { try await self.api.getTwoFactorEmail($0, proof: proof) }
                guard result.enabled, result.address == setup.address else { throw AccountTwoFactorError.changeUnconfirmed }
            }
        }
    }

    public func removeEmail(for lease: AccountSessionLease, password: String) async throws {
        try await exclusively {
            let proof = try await self.passwordProof(for: lease, password: password)
            let verified = try await self.request(for: lease) { try await self.api.getTwoFactorEmail($0, proof: proof) }
            guard verified.enabled else { throw AccountTwoFactorError.configurationChanged }
            try await self.removeMethod(.email, for: lease) {
                try await self.api.removeTwoFactorEmail($0, verified: verified)
            }
        }
    }

    public func securityKeys(for lease: AccountSessionLease, password: String) async throws -> [TwoFactorSecurityKey] {
        try await exclusively {
            let proof = try await self.passwordProof(for: lease, password: password)
            return try await self.request(for: lease) { try await self.api.getTwoFactorSecurityKeys($0, proof: proof).keys }
        }
    }

    /// Fetches a password-verified, state-bound server challenge for exactly one native prompt.
    /// No token is returned to the UI, and a cancelled, rejected or ambiguous attempt must start anew.
    public func registerSecurityKey(
        name: String, for lease: AccountSessionLease, password: String,
        isAvailable: @Sendable (ServerEnvironment) async -> Bool,
        authorize: @Sendable (TwoFactorSecurityKeyRegistrationChallenge, ServerEnvironment) async throws -> TwoFactorSecurityKeyAttestation
    ) async throws -> [TwoFactorSecurityKey] {
        let keyName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard (1...64).contains(keyName.utf8.count), keyName.rangeOfCharacter(from: .controlCharacters) == nil else {
            throw AccountTwoFactorError.invalidKeyName
        }
        return try await exclusively {
            let account = try await self.securityKeyRegistrationAccount(for: lease)
            let environment = account.environment
            guard await isAvailable(environment) else { throw WebAuthnSecondFactorError.unsupported }
            let proof = try await self.passwordProof(for: lease, password: password)
            let state = try await self.request(for: lease) { try await self.api.getTwoFactorSecurityKeys($0, proof: proof) }
            // Gap-fill the client-assigned management ID, as the web vault does. Cap
            // native enrollment at the assertion path's allowed-credential list limit.
            guard state.keys.count < 64 else { throw AccountTwoFactorError.securityKeyLimit }
            let ids = Set(state.keys.map(\.id))
            guard let id = (Int32(1)...Int32(ids.count + 1)).first(where: { !ids.contains($0) }) else {
                throw AccountTwoFactorError.configurationChanged
            }
            let requestedAt = ContinuousClock.now
            let challenge = try await self.request(for: lease) {
                try await self.api.getTwoFactorSecurityKeyChallenge($0, environment: environment, email: account.email, verified: state)
            }
            let expiresAt = requestedAt + .milliseconds(challenge.timeoutMilliseconds)
            try await self.check(lease)
            guard .now < expiresAt else { throw AccountTwoFactorError.setupExpired }
            let attestation = try await authorize(challenge, environment)
            try await self.check(lease)
            guard .now < expiresAt else { throw AccountTwoFactorError.setupExpired }
            try challenge.validate(attestation)
            return try await self.confirmChange(for: lease) {
                try await self.request(for: lease, changing: true) {
                    guard .now < expiresAt else { throw AccountTwoFactorError.setupExpired }
                    return try await self.api.registerTwoFactorSecurityKey($0, id: id, name: keyName, challenge: challenge,
                                                                          attestation: attestation, verified: state)
                }
            }
        }
    }

    private func securityKeyRegistrationAccount(for lease: AccountSessionLease) async throws
        -> (environment: ServerEnvironment, email: String) {
        try await check(lease)
        guard let session = await auth.session, session.accountID == lease.accountID,
              let environment = ServerEnvironment(string: session.serverURL),
              (try? TwoFactorSecurityKeyRegistrationChallenge.relyingPartyIdentifier(for: environment)) != nil else {
            throw WebAuthnSecondFactorError.unsupported
        }
        try await check(lease)
        return (environment, session.email)
    }

    public func removeSecurityKey(_ key: TwoFactorSecurityKey, for lease: AccountSessionLease,
                                  password: String) async throws -> [TwoFactorSecurityKey] {
        try await exclusively {
            let proof = try await self.passwordProof(for: lease, password: password)
            let verified = try await self.request(for: lease) { try await self.api.getTwoFactorSecurityKeys($0, proof: proof) }
            guard verified.enabled, verified.keys.contains(key) else { throw AccountTwoFactorError.configurationChanged }
            return try await self.confirmChange(for: lease) {
                let remaining = try await self.request(for: lease, changing: true) {
                    try await self.api.removeTwoFactorSecurityKey($0, id: key.id, verified: verified)
                }
                let expected = verified.keys.filter { $0.id != key.id }
                guard Set(remaining.map(\.id)) == Set(expected.map(\.id)) else {
                    throw AccountTwoFactorError.changeUnconfirmed
                }
                return remaining
            }
        }
    }

    public func revealRecoveryCode(for lease: AccountSessionLease, password: String) async throws -> String? {
        try await exclusively {
            let proof = try await self.passwordProof(for: lease, password: password)
            return try await self.request(for: lease) { try await self.api.getTwoFactorRecoveryCode($0, proof: proof) }
        }
    }

    private func exclusively<Result: Sendable>(_ action: @Sendable () async throws -> Result) async throws -> Result {
        try Task.checkCancellation()
        guard !isBusy else { throw AccountTwoFactorError.busy }
        isBusy = true
        defer { isBusy = false }
        return try await action()
    }

    private func newSetup(for lease: AccountSessionLease) -> AccountTwoFactorSetupStamp {
        let id = UUID()
        currentSetupID = id
        // Vaultwarden's server verification token expires in five minutes.
        return AccountTwoFactorSetupStamp(id: id, lease: lease, expiresAt: .now + .seconds(300))
    }

    private func checkSetup(_ stamp: AccountTwoFactorSetupStamp, for lease: AccountSessionLease) async throws {
        try await check(lease)
        guard stamp.lease == lease, stamp.id == currentSetupID, .now < stamp.expiresAt else {
            throw AccountTwoFactorError.setupExpired
        }
    }

    private func changeSetup(for lease: AccountSessionLease,
                             _ action: @Sendable (TwoFactorRequestContext) async throws -> Void) async throws {
        do {
            try await request(for: lease, changing: true, action)
            currentSetupID = nil
        } catch {
            // A rejected one-time code can be replaced; an uncertain result cannot be retried blindly.
            if error as? AccountTwoFactorError != .serverRejected { currentSetupID = nil }
            throw error
        }
    }

    private func removeMethod(_ provider: TwoFactorProvider, for lease: AccountSessionLease,
                              _ action: @Sendable (TwoFactorRequestContext) async throws -> Void) async throws {
        // Vaultwarden can fail a follow-up (for example, organization policy enforcement)
        // after deleting the method. Do not assume an HTTP failure means nothing changed.
        try await confirmChange(for: lease) {
            try await self.request(for: lease, changing: true, action)
            let current = try await self.methods(for: lease)
            guard !current.contains(where: { $0.provider == provider && $0.enabled }) else {
                throw AccountTwoFactorError.changeUnconfirmed
            }
        }
    }

    private func confirmChange<Result: Sendable>(for lease: AccountSessionLease,
                                                 _ confirmed: @Sendable () async throws -> Result) async throws -> Result {
        do { return try await confirmed() }
        catch {
            try await check(lease)
            throw AccountTwoFactorError.changeUnconfirmed
        }
    }

    private func passwordProof(for lease: AccountSessionLease, password: String) async throws -> String {
        try await check(lease)
        let proof = try await auth.authorizeAccountAction(for: lease, password: password)
        try await check(lease)
        return proof
    }

    private func request<Result: Sendable>(for lease: AccountSessionLease, changing: Bool = false,
                                            _ action: @Sendable (TwoFactorRequestContext) async throws -> Result) async throws -> Result {
        try await check(lease)
        do {
            let contextID = try await auth.accountActionContext(for: lease)
            try await check(lease)
            let result = try await action(TwoFactorRequestContext(accountID: lease.accountID, contextID: contextID))
            try await check(lease)
            return result
        } catch {
            try await check(lease)
            // Never surface raw upstream response bodies or decoding diagnostics for these routes.
            switch error {
            case NetworkingError.accountContextChanged: throw RepositoryError.locked
            case NetworkingError.unauthorized, NetworkingError.accessTokenUnavailable,
                 RepositoryError.authenticationFailed, RepositoryError.notAuthenticated:
                throw RepositoryError.notAuthenticated
            case NetworkingError.http(status: 404, body: _), NetworkingError.http(status: 405, body: _):
                throw AccountTwoFactorError.unsupportedServer
            case NetworkingError.http(status: 400, body: _), NetworkingError.http(status: 403, body: _),
                 NetworkingError.http(status: 429, body: _):
                throw AccountTwoFactorError.serverRejected
            case NetworkingError.decoding where !changing: throw AccountTwoFactorError.unsupportedServer
            default: throw changing ? AccountTwoFactorError.changeUnconfirmed : AccountTwoFactorError.requestFailed
            }
        }
    }

    private func check(_ lease: AccountSessionLease) async throws {
        try Task.checkCancellation()
        guard await auth.unlockedSessionLease() == lease else { throw RepositoryError.locked }
        try Task.checkCancellation()
    }

    private static func isLoginCode(_ value: String) -> Bool {
        value.utf8.count == 6 && value.utf8.allSatisfy { (48...57).contains($0) }
    }

    private static func validateEmailAddress(_ input: String) throws -> String {
        let address = input.trimmingCharacters(in: .whitespacesAndNewlines)
        let parts = address.split(separator: "@", omittingEmptySubsequences: false)
        guard address.utf8.count <= 254, parts.count == 2, parts.allSatisfy({ !$0.isEmpty }),
              address.rangeOfCharacter(from: .whitespacesAndNewlines.union(.controlCharacters)) == nil else {
            throw AccountTwoFactorError.invalidEmail
        }
        return address
    }
}
