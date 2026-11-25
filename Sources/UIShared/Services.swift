import Foundation
import VaultModels
import Networking
import SyncEngine
import VaultRepository

// MARK: - View-model-facing service protocols
//
// The `@Observable` view models depend on these PROTOCOLS rather than the concrete
// `AuthRepository` / `VaultRepository` actors, so tests inject in-memory fakes. The real
// repositories are made to conform via thin adapters below — the adapters bind the
// per-session context (server URL, biometric-enable flag) that the VM-facing API should
// not have to thread through.

/// The authentication / unlock surface a view model needs.
///
/// Note the deliberately narrowed signatures versus `AuthRepository`:
/// - `login`/`submitTwoFactor` drop the `server:`/`enableBiometrics:` parameters — those are
///   bound once at container-build time by `AuthServiceAdapter` (the VM only knows the
///   already-entered server URL via `LoginModel.serverURL`, which the adapter is configured with).
/// - `submitTwoFactor` takes the raw `provider` + `code` the UI collected.
public protocol AuthService: Sendable {
    func transferSession() async -> AccountSessionLease?
    func verifyTransferPassword(_ password: String, for lease: AccountSessionLease) async throws
    func login(email: String, password: String, serverURL: String) async throws -> LoginResult
    func submitTwoFactor(provider: TwoFactorProvider, code: String,
                         remember: Bool, serverURL: String) async throws -> LoginResult
    func submitSecurityKey(remember: Bool, serverURL: String) async throws -> LoginResult
    func sendTwoFactorEmail(serverURL: String) async throws
    func requestPasswordHint(email: String, serverURL: String) async throws
    func cancelTwoFactor(email: String, serverURL: String) async
    func accountEmail() async -> String?
    func accountKDFIterations() async -> Int?
    func requiresNewLogin() async -> Bool
    func unlockWithMasterPassword(_ password: String) async throws
    func unlockWithBiometrics(reason: String) async throws
    func isUnlocked() async -> Bool
    func setBiometricUnlockEnabled(_ enabled: Bool) async throws
    func hasSession() async -> Bool
    func lock() async
    @discardableResult func logout() async -> Bool
}

/// The vault read/CRUD/sync surface a view model needs.
public protocol VaultService: Sendable {
    var syncAccess: VaultSyncAccess? { get }
    var sendService: (any VaultSendService)? { get }
    func exportArchive(for lease: AccountSessionLease) async throws -> VaultTransferArchive
    func importCiphers(_ items: [PlaintextCipher], for lease: AccountSessionLease) async throws
    func importFolder(name: String, for lease: AccountSessionLease) async throws -> String
    func ciphers() async throws -> [PlaintextCipher]
    func recentItemIDs(limit: Int) async throws -> [String]
    func recordUse(id: String) async
    func listing() async throws -> VaultListing
    func archivedCiphers() async throws -> [PlaintextCipher]
    func trashedCiphers() async throws -> [PlaintextCipher]
    func folders() async throws -> [PlaintextFolder]
    func createFolder(name: String) async throws -> String
    func renameFolder(id: String, name: String) async throws
    func deleteFolder(id: String) async throws
    func cipher(id: String) async throws -> PlaintextCipher
    func sshAgentIdentities(for lease: AccountSessionLease) async throws -> [VaultSSHAgentIdentity]
    func sshAgentSigningKey(matching identity: VaultSSHAgentIdentity, for lease: AccountSessionLease) async throws -> String
    func isSSHAgentIdentityCurrent(_ identity: VaultSSHAgentIdentity, for lease: AccountSessionLease) async throws -> Bool
    func search(_ query: String) async throws -> [PlaintextCipher]
    func createCipher(_ cipher: PlaintextCipher) async throws -> String
    func updateCipher(id: String, _ cipher: PlaintextCipher) async throws
    func trashCipher(id: String) async throws
    func restoreCipher(id: String) async throws
    func archiveCipher(id: String) async throws
    func unarchiveCipher(id: String) async throws
    func permanentlyDeleteCipher(id: String) async throws
    func upgradeLegacyCipherKeys(for session: AccountSessionLease) async throws -> CipherKeyUpgradeResult
    func outboxStatus(for session: AccountSessionLease?) async throws -> VaultOutboxStatus
    func resolveOutboxIssue(_ issue: VaultOutboxIssue, action: VaultOutboxAction, for session: AccountSessionLease?) async throws
    func sync() async throws -> SyncOutcome
    func sync(for session: AccountSessionLease) async throws -> SyncOutcome
}

public extension VaultService {
    var syncAccess: VaultSyncAccess? { nil }
    var sendService: (any VaultSendService)? { nil }

    func sshAgentIdentities(for lease: AccountSessionLease) async throws -> [VaultSSHAgentIdentity] { [] }
    func sshAgentSigningKey(matching identity: VaultSSHAgentIdentity, for lease: AccountSessionLease) async throws -> String {
        throw RepositoryError.vaultAccessDenied
    }
    func isSSHAgentIdentityCurrent(_ identity: VaultSSHAgentIdentity, for lease: AccountSessionLease) async throws -> Bool { false }

    func upgradeLegacyCipherKeys(for session: AccountSessionLease) async throws -> CipherKeyUpgradeResult {
        throw RepositoryError.notAuthenticated
    }
    func outboxStatus(for session: AccountSessionLease?) async throws -> VaultOutboxStatus { VaultOutboxStatus() }
    func resolveOutboxIssue(_ issue: VaultOutboxIssue, action: VaultOutboxAction, for session: AccountSessionLease?) async throws {
        throw RepositoryError.outboxRecoveryUnavailable
    }

    func sync(for session: AccountSessionLease) async throws -> SyncOutcome { try await sync() }

    func synchronize(access: VaultSyncAccess? = nil) async throws -> SyncOutcome {
        guard let scope = access ?? syncAccess else { return try await sync() }
        return try await scope.perform { session in try await self.sync(for: session) }
    }
}

// MARK: - Concrete adapters (real repositories → VM-facing protocols)

/// Adapts the real `AuthRepository` actor to `AuthService`.
///
/// `AuthRepository.login` requires a `ServerEnvironment` and an `enableBiometrics` flag that
/// the VM-facing protocol does not carry. This adapter parses the VM's `serverURL` string into
/// a `ServerEnvironment` and supplies the `enableBiometrics` policy captured at construction,
/// so the view model never imports `Networking.ServerEnvironment`.
public extension AuthService {
    func requiresNewLogin() async -> Bool { false }

    func submitSecurityKey(remember: Bool, serverURL: String) async throws -> LoginResult {
        throw WebAuthnSecondFactorError.unsupported
    }
}

public struct AuthServiceAdapter: AuthService {
    public typealias SecurityKeyAuthorizer = @MainActor @Sendable (WebAuthnSecondFactorChallenge, ServerEnvironment) async throws -> String

    private let repository: AuthRepository
    private let securityKeyAuthorizer: SecurityKeyAuthorizer?
    private let allowsServer: @Sendable (ServerEnvironment) -> Bool
    private let onLock: @Sendable () async -> Void
    /// Dynamic policy so changing Settings does not require rebuilding the app graph.
    private let biometricPolicy: @Sendable () async -> Bool
    private let onAccountChanged: @Sendable () async -> Void

    public init(
        repository: AuthRepository,
        enableBiometrics: Bool = false,
        onAccountChanged: @escaping @Sendable () async -> Void = {}
    ) {
        self.init(repository: repository, biometricPolicy: { enableBiometrics }, onAccountChanged: onAccountChanged)
    }

    public init(
        repository: AuthRepository,
        biometricPolicy: @escaping @Sendable () async -> Bool,
        securityKeyAuthorizer: SecurityKeyAuthorizer? = nil,
        allowsServer: @escaping @Sendable (ServerEnvironment) -> Bool = { $0.base.scheme == "https" },
        onLock: @escaping @Sendable () async -> Void = {},
        onAccountChanged: @escaping @Sendable () async -> Void = {}
    ) {
        self.repository = repository
        self.biometricPolicy = biometricPolicy
        self.securityKeyAuthorizer = securityKeyAuthorizer
        self.allowsServer = allowsServer
        self.onLock = onLock
        self.onAccountChanged = onAccountChanged
    }

    public func login(email: String, password: String, serverURL: String) async throws -> LoginResult {
        let server = try validatedEnvironment(serverURL)
        let intent = await repository.reserveAuthenticationIntent()
        await onAccountChanged()
        guard await repository.isAuthenticationIntentCurrent(intent) else {
            throw RepositoryError.underlying(
                kind: .network,
                description: "Authentication intent was superseded"
            )
        }
        let enableBiometrics = await biometricPolicy()
        guard await repository.isAuthenticationIntentCurrent(intent) else {
            throw RepositoryError.underlying(
                kind: .network,
                description: "Authentication intent was superseded"
            )
        }
        let result = try await repository.login(email: email, password: password,
                                                server: server,
                                                enableBiometrics: enableBiometrics,
                                                reservedIntent: intent)
        if result == .success { await onAccountChanged() }
        return result
    }

    public func submitTwoFactor(provider: TwoFactorProvider, code: String,
                                remember: Bool, serverURL: String) async throws -> LoginResult {
        let server = try validatedEnvironment(serverURL)
        let enableBiometrics = await biometricPolicy()
        let result = try await repository.submitTwoFactor(
            provider: provider,
            token: code,
            remember: remember,
            server: server,
            enableBiometrics: enableBiometrics
        )
        if result == .success { await onAccountChanged() }
        return result
    }

    public func submitSecurityKey(remember: Bool, serverURL: String) async throws -> LoginResult {
        guard let securityKeyAuthorizer else { throw WebAuthnSecondFactorError.unsupported }
        let server = try validatedEnvironment(serverURL)
        let attempt = try await repository.securityKeyAttempt(server: server)
        let assertion = try await securityKeyAuthorizer(attempt.challenge, server)
        try Task.checkCancellation()
        let result = try await repository.submitSecurityKey(attempt, token: assertion, remember: remember,
                                                            server: server, enableBiometrics: await biometricPolicy())
        if result == .success { await onAccountChanged() }
        return result
    }

    public func sendTwoFactorEmail(serverURL: String) async throws {
        try await repository.sendTwoFactorEmail(server: validatedEnvironment(serverURL))
    }

    public func requestPasswordHint(email: String, serverURL: String) async throws {
        try await repository.requestPasswordHint(email: email, server: validatedEnvironment(serverURL))
    }

    public func cancelTwoFactor(email: String, serverURL: String) async {
        guard let server = ServerEnvironment(string: serverURL) else { return }
        await repository.cancelTwoFactor(email: email, server: server)
    }

    public func accountEmail() async -> String? { await repository.session?.email }
    public func accountKDFIterations() async -> Int? { await repository.session?.kdfIterations }
    public func requiresNewLogin() async -> Bool { await repository.requiresNewLogin() }

    public func unlockWithMasterPassword(_ password: String) async throws {
        try await repository.unlockWithMasterPassword(password)
        await onAccountChanged()
    }

    public func unlockWithBiometrics(reason: String) async throws {
        try await repository.unlockWithBiometrics(reason: reason)
        await onAccountChanged()
    }

    public func isUnlocked() async -> Bool {
        await repository.isUnlocked()
    }

    public func transferSession() async -> AccountSessionLease? {
        await repository.unlockedSessionLease()
    }

    public func verifyTransferPassword(_ password: String, for lease: AccountSessionLease) async throws {
        try await repository.verifyMasterPassword(password, for: lease)
    }

    public func setBiometricUnlockEnabled(_ enabled: Bool) async throws {
        try await repository.setBiometricUnlockEnabled(enabled)
    }

    public func hasSession() async -> Bool {
        await repository.hasSession()
    }

    public func lock() async {
        await repository.lock()
        await onLock()
    }

    @discardableResult
    public func logout() async -> Bool {
        let intent = await repository.reserveAuthenticationIntent()
        guard await repository.logout(reservedIntent: intent) else { return false }
        if await repository.isAuthenticationIntentCurrent(intent) {
            await onAccountChanged()
        }
        return true
    }

    private func validatedEnvironment(_ serverURL: String) throws -> ServerEnvironment {
        let server = try Self.makeEnvironment(serverURL)
        guard allowsServer(server) else {
            throw RepositoryError.underlying(kind: .network, description: "HTTPS is required for this server")
        }
        return server
    }

    /// Parse the user-entered server URL into a `ServerEnvironment`, or throw a clear
    /// repository error so the UI can show "invalid server URL".
    static func makeEnvironment(_ serverURL: String) throws -> ServerEnvironment {
        guard let env = ServerEnvironment(string: serverURL) else {
            throw RepositoryError.underlying(kind: .network, description: "Invalid server URL")
        }
        return env
    }
}

/// Adapts the real `VaultRepository` actor to `VaultService` (signatures already match;
/// the conformance just forwards each call across the actor boundary).
public struct VaultServiceAdapter: VaultService {
    public let syncAccess: VaultSyncAccess?
    public let sendService: (any VaultSendService)?
    private let repository: VaultRepository
    private let beforeAccess: @Sendable () async -> Void

    public init(
        repository: VaultRepository,
        sendService: (any VaultSendService)? = nil,
        syncAccess: VaultSyncAccess? = nil,
        beforeAccess: @escaping @Sendable () async -> Void = {}
    ) {
        self.repository = repository
        self.beforeAccess = beforeAccess
        self.sendService = sendService
        self.syncAccess = syncAccess
    }

    public func ciphers() async throws -> [PlaintextCipher] {
        await beforeAccess()
        return try await repository.ciphers()
    }

    public func recentItemIDs(limit: Int) async throws -> [String] {
        try await repository.recentItemIDs(limit: limit)
    }

    public func recordUse(id: String) async {
        await repository.recordUse(id: id)
    }
    public func cipher(id: String) async throws -> PlaintextCipher {
        await beforeAccess()
        return try await repository.cipher(id: id)
    }
    public func sshAgentIdentities(for lease: AccountSessionLease) async throws -> [VaultSSHAgentIdentity] {
        try await repository.sshAgentIdentities(for: lease)
    }
    public func sshAgentSigningKey(matching identity: VaultSSHAgentIdentity, for lease: AccountSessionLease) async throws -> String {
        try await repository.sshAgentSigningKey(matching: identity, for: lease)
    }
    public func isSSHAgentIdentityCurrent(_ identity: VaultSSHAgentIdentity, for lease: AccountSessionLease) async throws -> Bool {
        try await repository.isSSHAgentIdentityCurrent(identity, for: lease)
    }
    public func exportArchive(for lease: AccountSessionLease) async throws -> VaultTransferArchive {
        await beforeAccess()
        let snapshot = try await repository.exportSnapshot(expectedSession: lease)
        return VaultTransferArchive(folders: snapshot.folders, items: snapshot.items)
    }
    public func importCiphers(_ items: [PlaintextCipher], for lease: AccountSessionLease) async throws {
        await beforeAccess()
        try await repository.importCiphers(items, expectedSession: lease)
    }
    public func importFolder(name: String, for lease: AccountSessionLease) async throws -> String {
        await beforeAccess()
        return try await repository.createFolder(name: name, expectedSession: lease)
    }
    public func search(_ query: String) async throws -> [PlaintextCipher] {
        await beforeAccess()
        return try await repository.search(query)
    }
    public func createCipher(_ cipher: PlaintextCipher) async throws -> String {
        await beforeAccess()
        return try await repository.createCipher(cipher)
    }
    public func updateCipher(id: String, _ cipher: PlaintextCipher) async throws {
        await beforeAccess()
        try await repository.updateCipher(id: id, cipher)
    }
    public func archivedCiphers() async throws -> [PlaintextCipher] {
        await beforeAccess()
        return try await repository.archivedCiphers()
    }
    public func listing() async throws -> VaultListing {
        await beforeAccess()
        return try await repository.listing()
    }
    public func trashedCiphers() async throws -> [PlaintextCipher] {
        await beforeAccess()
        return try await repository.trashedCiphers()
    }
    public func folders() async throws -> [PlaintextFolder] {
        await beforeAccess()
        return try await repository.folders()
    }
    public func createFolder(name: String) async throws -> String {
        await beforeAccess()
        return try await repository.createFolder(name: name)
    }
    public func renameFolder(id: String, name: String) async throws {
        await beforeAccess()
        try await repository.renameFolder(id: id, name: name)
    }
    public func deleteFolder(id: String) async throws {
        await beforeAccess()
        try await repository.deleteFolder(id: id)
    }
    public func trashCipher(id: String) async throws {
        await beforeAccess()
        try await repository.changeCipherVisibility(id: id, change: .trash)
    }
    public func restoreCipher(id: String) async throws {
        await beforeAccess()
        try await repository.changeCipherVisibility(id: id, change: .restore)
    }
    public func archiveCipher(id: String) async throws {
        await beforeAccess()
        try await repository.changeCipherVisibility(id: id, change: .archive)
    }
    public func unarchiveCipher(id: String) async throws {
        await beforeAccess()
        try await repository.changeCipherVisibility(id: id, change: .unarchive)
    }
    public func permanentlyDeleteCipher(id: String) async throws {
        await beforeAccess()
        try await repository.permanentlyDeleteCipher(id: id)
    }

    public func upgradeLegacyCipherKeys(for session: AccountSessionLease) async throws -> CipherKeyUpgradeResult {
        try await repository.upgradeLegacyCipherKeys(expectedSession: session)
    }

    public func outboxStatus(for session: AccountSessionLease?) async throws -> VaultOutboxStatus {
        try await repository.outboxStatus(expectedSession: session)
    }

    public func resolveOutboxIssue(_ issue: VaultOutboxIssue, action: VaultOutboxAction, for session: AccountSessionLease?) async throws {
        await beforeAccess()
        try await repository.resolveOutboxIssue(issue, action: action, expectedSession: session)
    }

    public func sync() async throws -> SyncOutcome {
        await beforeAccess()
        return try await repository.sync()
    }

    public func sync(for session: AccountSessionLease) async throws -> SyncOutcome {
        await beforeAccess()
        return try await repository.sync(expectedSession: session)
    }
}

extension VaultServiceAdapter: GeneratorHistoryService {
    public func generatorHistory() async throws -> GeneratorHistorySnapshot {
        try await repository.generatorHistory()
    }

    public func addGeneration(_ entry: GeneratorHistoryEntry, session: AccountSessionLease) async throws {
        try await repository.addGeneration(entry, session: session)
    }

    public func clearGeneratorHistory(session: AccountSessionLease) async throws {
        try await repository.clearGeneratorHistory(session: session)
    }
}
