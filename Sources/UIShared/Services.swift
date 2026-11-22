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
    func sendTwoFactorEmail(serverURL: String) async throws
    func requestPasswordHint(email: String, serverURL: String) async throws
    func cancelTwoFactor(email: String, serverURL: String) async
    func accountEmail() async -> String?
    func accountKDFIterations() async -> Int?
    func unlockWithMasterPassword(_ password: String) async throws
    func unlockWithBiometrics(reason: String) async throws
    func isUnlocked() async -> Bool
    func setBiometricUnlockEnabled(_ enabled: Bool) async throws
    func hasSession() async -> Bool
    func lock() async
    func logout() async
}

/// The vault read/CRUD/sync surface a view model needs.
public protocol VaultService: Sendable {
    var sendService: (any VaultSendService)? { get }
    func exportableCiphers(for lease: AccountSessionLease) async throws -> [PlaintextCipher]
    func exportableFolders(for lease: AccountSessionLease) async throws -> [PlaintextFolder]
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
    func search(_ query: String) async throws -> [PlaintextCipher]
    func createCipher(_ cipher: PlaintextCipher) async throws -> String
    func updateCipher(id: String, _ cipher: PlaintextCipher) async throws
    func trashCipher(id: String) async throws
    func restoreCipher(id: String) async throws
    func archiveCipher(id: String) async throws
    func unarchiveCipher(id: String) async throws
    func permanentlyDeleteCipher(id: String) async throws
    func sync() async throws -> SyncOutcome
}

public extension VaultService {
    var sendService: (any VaultSendService)? { nil }
}

// MARK: - Concrete adapters (real repositories → VM-facing protocols)

/// Adapts the real `AuthRepository` actor to `AuthService`.
///
/// `AuthRepository.login` requires a `ServerEnvironment` and an `enableBiometrics` flag that
/// the VM-facing protocol does not carry. This adapter parses the VM's `serverURL` string into
/// a `ServerEnvironment` and supplies the `enableBiometrics` policy captured at construction,
/// so the view model never imports `Networking.ServerEnvironment`.
public struct AuthServiceAdapter: AuthService {
    private let repository: AuthRepository
    /// Dynamic policy so changing Settings does not require rebuilding the app graph.
    private let biometricPolicy: @Sendable () async -> Bool
    private let onAccountChanged: @Sendable () async -> Void

    public init(
        repository: AuthRepository,
        enableBiometrics: Bool = false,
        onAccountChanged: @escaping @Sendable () async -> Void = {}
    ) {
        self.repository = repository
        self.biometricPolicy = { enableBiometrics }
        self.onAccountChanged = onAccountChanged
    }

    public init(
        repository: AuthRepository,
        biometricPolicy: @escaping @Sendable () async -> Bool,
        onAccountChanged: @escaping @Sendable () async -> Void = {}
    ) {
        self.repository = repository
        self.biometricPolicy = biometricPolicy
        self.onAccountChanged = onAccountChanged
    }

    public func login(email: String, password: String, serverURL: String) async throws -> LoginResult {
        let server = try Self.makeEnvironment(serverURL)
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
        let server = try Self.makeEnvironment(serverURL)
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

    public func sendTwoFactorEmail(serverURL: String) async throws {
        try await repository.sendTwoFactorEmail(
            server: Self.makeEnvironment(serverURL)
        )
    }

    public func requestPasswordHint(email: String, serverURL: String) async throws {
        try await repository.requestPasswordHint(email: email, server: Self.makeEnvironment(serverURL))
    }

    public func cancelTwoFactor(email: String, serverURL: String) async {
        guard let server = ServerEnvironment(string: serverURL) else { return }
        await repository.cancelTwoFactor(email: email, server: server)
    }

    public func accountEmail() async -> String? { await repository.session?.email }
    public func accountKDFIterations() async -> Int? { await repository.session?.kdfIterations }

    public func unlockWithMasterPassword(_ password: String) async throws {
        try await repository.unlockWithMasterPassword(password)
    }

    public func unlockWithBiometrics(reason: String) async throws {
        try await repository.unlockWithBiometrics(reason: reason)
    }

    public func isUnlocked() async -> Bool {
        await repository.isUnlocked()
    }

    public func transferSession() async -> AccountSessionLease? {
        guard await repository.isUnlocked() else { return nil }
        return await repository.currentSessionLease()
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
    }

    public func logout() async {
        let intent = await repository.reserveAuthenticationIntent()
        await repository.logout(reservedIntent: intent)
        if await repository.isAuthenticationIntentCurrent(intent) {
            await onAccountChanged()
        }
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
    public let sendService: (any VaultSendService)?
    private let repository: VaultRepository
    private let beforeAccess: @Sendable () async -> Void

    public init(
        repository: VaultRepository,
        sendService: (any VaultSendService)? = nil,
        beforeAccess: @escaping @Sendable () async -> Void = {}
    ) {
        self.repository = repository
        self.beforeAccess = beforeAccess
        self.sendService = sendService
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
    public func exportableCiphers(for lease: AccountSessionLease) async throws -> [PlaintextCipher] {
        await beforeAccess()
        return try await repository.exportableCiphers(expectedSession: lease)
    }
    public func exportableFolders(for lease: AccountSessionLease) async throws -> [PlaintextFolder] {
        await beforeAccess()
        return try await repository.exportableFolders(expectedSession: lease)
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
    public func sync() async throws -> SyncOutcome {
        await beforeAccess()
        return try await repository.sync()
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
