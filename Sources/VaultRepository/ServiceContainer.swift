import Foundation
import CryptoCore
import VaultModels
import VaultStore
import KeyVault
import KeychainBridge
import Networking
import SyncEngine
import AppShared

/// Dependency-injection container (design spec §5.9), mirroring the official Bitwarden iOS
/// app's `ServiceContainer` + `Has<Service>` pattern.
///
/// View models declare what they need via the `Has*` protocols and receive a container that
/// resolves the concrete repositories. Tests build a container from fakes; the app uses
/// `ServiceContainer.makeDefault(...)`.
public final class ServiceContainer: Sendable {
    public let authRepository: AuthRepository
    public let vaultRepository: VaultRepository
    /// The one process-wide sync actor shared by foreground repository calls and app
    /// lifecycle/background refresh. Multiple engines over one outbox can send a row twice.
    public let syncEngine: SyncEngine
    public let store: VaultStore
    public let keyVault: KeyVault
    public let keychain: KeychainBridge

    public init(authRepository: AuthRepository, vaultRepository: VaultRepository,
                syncEngine: SyncEngine,
                store: VaultStore, keyVault: KeyVault, keychain: KeychainBridge) {
        self.authRepository = authRepository
        self.vaultRepository = vaultRepository
        self.syncEngine = syncEngine
        self.store = store
        self.keyVault = keyVault
        self.keychain = keychain
    }

    /// Build the default production container from the lower-level services.
    ///
    /// Wires a single shared `KeyVault` + write-path `UserKeyEncryptor` across both
    /// repositories (so unlock/lock affect both), a `SyncEngine` over the real `APIClient`,
    /// and resolves the active account id from the `AuthRepository`'s session.
    public static func makeDefault(apiClient: APIClient, store: VaultStore, keychain: KeychainBridge,
                                   identityStore: CredentialIdentityWriting) -> ServiceContainer {
        let keyVault = KeyVault()
        let encryptor = UserKeyEncryptor()

        let authRepository = AuthRepository(api: apiClient, keyVault: keyVault, keychain: keychain,
                                            store: store, encryptor: encryptor)
        let mutationCoordinator = VaultMutationCoordinator()
        let syncEngine = SyncEngine(
            api: apiClient,
            store: store,
            keyVault: keyVault,
            identityStore: identityStore,
            mutationCoordinator: mutationCoordinator
        )
        let vaultRepository = VaultRepository(
            api: apiClient, store: store, keyVault: keyVault, encryptor: encryptor,
            syncEngine: syncEngine,
            mutationCoordinator: mutationCoordinator,
            accountLease: { await authRepository.currentSessionLease() },
            lockHandler: { await authRepository.lock() }
        )

        return ServiceContainer(authRepository: authRepository, vaultRepository: vaultRepository,
                                syncEngine: syncEngine,
                                store: store, keyVault: keyVault, keychain: keychain)
    }
}

// MARK: - Has<Service> protocols

/// A type that can resolve an `AuthRepository`.
public protocol HasAuthRepository: Sendable {
    var authRepository: AuthRepository { get }
}

/// A type that can resolve a `VaultRepository`.
public protocol HasVaultRepository: Sendable {
    var vaultRepository: VaultRepository { get }
}

public protocol HasSyncEngine: Sendable {
    var syncEngine: SyncEngine { get }
}

/// A type that can resolve the shared `KeyVault`.
public protocol HasKeyVault: Sendable {
    var keyVault: KeyVault { get }
}

/// A type that can resolve the `VaultStore`.
public protocol HasVaultStore: Sendable {
    var store: VaultStore { get }
}

/// A type that can resolve the `KeychainBridge`.
public protocol HasKeychain: Sendable {
    var keychain: KeychainBridge { get }
}

/// The container conforms to every `Has*` protocol, so a view model can depend on just the
/// services it needs (e.g. `some HasAuthRepository & HasVaultRepository`).
extension ServiceContainer: HasAuthRepository, HasVaultRepository, HasSyncEngine,
                            HasKeyVault, HasVaultStore, HasKeychain {}
