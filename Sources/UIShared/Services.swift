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
// not have to thread through, keeping the protocols clean (design note in the M1 plan §G).

/// The authentication / unlock surface a view model needs.
///
/// Note the deliberately narrowed signatures versus `AuthRepository`:
/// - `login`/`submitTwoFactor` drop the `server:`/`enableBiometrics:` parameters — those are
///   bound once at container-build time by `AuthServiceAdapter` (the VM only knows the
///   already-entered server URL via `LoginModel.serverURL`, which the adapter is configured with).
/// - `submitTwoFactor` takes the raw `provider` + `code` the UI collected.
public protocol AuthService: Sendable {
    func login(email: String, password: String, serverURL: String) async throws -> LoginResult
    func submitTwoFactor(provider: TwoFactorProvider, code: String,
                         remember: Bool, serverURL: String) async throws -> LoginResult
    func sendTwoFactorEmail(serverURL: String) async throws
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
    func ciphers() async throws -> [PlaintextCipher]
    func cipher(id: String) async throws -> PlaintextCipher
    func search(_ query: String) async throws -> [PlaintextCipher]
    func createCipher(_ cipher: PlaintextCipher) async throws -> String
    func updateCipher(id: String, _ cipher: PlaintextCipher) async throws
    func deleteCipher(id: String) async throws
    func sync() async throws -> SyncOutcome
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

    public func unlockWithMasterPassword(_ password: String) async throws {
        try await repository.unlockWithMasterPassword(password)
    }

    public func unlockWithBiometrics(reason: String) async throws {
        try await repository.unlockWithBiometrics(reason: reason)
    }

    public func isUnlocked() async -> Bool {
        await repository.isUnlocked()
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
    private let repository: VaultRepository
    private let beforeAccess: @Sendable () async -> Void

    public init(
        repository: VaultRepository,
        beforeAccess: @escaping @Sendable () async -> Void = {}
    ) {
        self.repository = repository
        self.beforeAccess = beforeAccess
    }

    public func ciphers() async throws -> [PlaintextCipher] {
        await beforeAccess()
        return try await repository.ciphers()
    }
    public func cipher(id: String) async throws -> PlaintextCipher {
        await beforeAccess()
        return try await repository.cipher(id: id)
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
    public func deleteCipher(id: String) async throws {
        await beforeAccess()
        try await repository.deleteCipher(id: id)
    }
    public func sync() async throws -> SyncOutcome {
        await beforeAccess()
        return try await repository.sync()
    }
}
