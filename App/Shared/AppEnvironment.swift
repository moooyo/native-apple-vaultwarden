// Xcode-only target. Not part of the SPM build.
//
// AppEnvironment — the production dependency-injection graph + app lifecycle glue, shared by
// the iOS and macOS app targets (design spec §5.9, blueprint §G).
//
// It builds the real services exactly once:
//   * `APIClient` (URLSession) over the persisted server URL + stable device metadata,
//   * `VaultStore` opened on the SQLCipher DB inside the App Group container (so the AutoFill
//     extension opens the SAME file), keyed by a random passphrase kept in the shared Keychain,
//   * a single shared `KeyVault` + `KeychainBridge`,
//   * the `ServiceContainer` (AuthRepository / VaultRepository / SyncEngine),
//   * the `ASCredentialIdentityWriter` so a sync rebuilds the AutoFill identity index.
//
// It also owns the cross-cutting lifecycle: auto-lock on background/timeout, background
// refresh registration + scheduling, and seeding an already-signed-in session at launch.
//
// `@MainActor @Observable` so the SwiftUI scenes can hold it as `@State` and the lock
// timestamp / settings binding stay on the main actor.

import Foundation
import Security
import Observation
import VaultModels
import Networking
import VaultStore
import KeyVault
import KeychainBridge
import SyncEngine
import VaultRepository
import UIShared
import AppShared
import PasskeyHandoff

#if canImport(BackgroundTasks)
import BackgroundTasks
#endif

@available(iOS 26.0, macOS 26.0, *)
@MainActor
@Observable
final class AppEnvironment {
    enum Platform { case iOS, macOS }

    // MARK: - Public, VM-facing services (what the scenes inject into views)

    /// The auth/unlock surface the views consume (real `AuthRepository` behind the protocol).
    let auth: AuthService
    /// The vault read/CRUD/sync surface the views consume.
    let vault: VaultService
    /// The editable settings model, hydrated from App Group `UserDefaults`.
    let settings: SettingsModel

    // MARK: - Concrete graph (retained for lifecycle: lock, sync, seed)

    private let container: ServiceContainer
    private let syncEngine: SyncEngine
    private let apiClient: APIClient
    private let platform: Platform
    private let defaults: UserDefaults
    private let passkeyDrainer: PasskeyRegistrationDrainer?

    /// Root views are created only after this flips to true, preventing their initial
    /// routing task from racing cold-session restoration.
    private(set) var didSeedSession = false
    /// Recreates root/menu views after lifecycle auto-lock so plaintext held in view state
    /// is released and routing immediately resolves to the unlock screen.
    private(set) var authStateGeneration: UInt64 = 0
    /// Advances after background/foreground sync or passkey import changes local vault data.
    private(set) var dataRevision: UInt64 = 0
    private var isSeedingSession = false
    private var isPerformingSync = false
    private var biometricSettingGeneration: UInt64 = 0

    /// Timestamp of the last resign-active, used to apply the auto-lock timeout on return.
    private var backgroundedAt: Date?

    #if os(macOS)
    /// macOS uses an `NSBackgroundActivityScheduler` (no BGTaskScheduler).
    private var macActivity: NSBackgroundActivityScheduler?
    #endif

    // MARK: - Construction

    init(platform: Platform) {
        self.platform = platform
        let defaults = UserDefaults(suiteName: AppShared.appGroupID) ?? .standard
        self.defaults = defaults

        // 1. Persisted settings (App Group UserDefaults — NEVER keys/tokens, design spec §5.6).
        let settings = AppEnvironment.loadSettings(from: defaults)
        self.settings = settings

        // 2. Stable device metadata (a per-install UUID persisted in the App Group).
        let device = AppEnvironment.deviceMetadata(platform: platform, defaults: defaults)

        // 3. Keychain bridge in the shared access group (cross-process key channel).
        let keychain = KeychainBridge(accessGroup: AppShared.keychainAccessGroup,
                                      service: "dev.moooyo.tessera")

        // 4. Encrypted offline store in the App Group container, keyed by a random passphrase
        //    that lives in the shared Keychain so the extension opens the same DB.
        let store = AppEnvironment.makeStore(keychain: keychain, defaults: defaults)

        // 5. API client over the persisted server (a placeholder base when none is set yet —
        //    the login flow rebuilds the client implicitly via the repository's ServerEnvironment).
        let environment = AppEnvironment.serverEnvironment(settings.serverURL)
        let apiClient = APIClient(environment: environment,
                                  session: .shared,
                                  device: device,
                                  clientVersion: AppEnvironment.clientVersion)
        self.apiClient = apiClient

        // 6. Compose the container + sync engine with the real AutoFill identity writer.
        let identityWriter = AppEnvironment.makeIdentityWriter()
        let container = ServiceContainer.makeDefault(apiClient: apiClient, store: store,
                                                     keychain: keychain,
                                                     identityStore: identityWriter)
        self.container = container
        self.syncEngine = container.syncEngine

        let passkeyDrainer = FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: AppShared.appGroupID)
            .map {
                PasskeyRegistrationDrainer(
                    handoff: PasskeyRegistrationHandoff(
                        directoryURL: $0.appendingPathComponent(
                            "passkey-handoff",
                            isDirectory: true
                        ),
                        keychain: keychain
                    ),
                    auth: container.authRepository,
                    vault: container.vaultRepository
                )
            }
        self.passkeyDrainer = passkeyDrainer

        // 7. VM-facing adapters (bind the per-session biometric policy from settings).
        self.auth = AuthServiceAdapter(
            repository: container.authRepository,
            biometricPolicy: { await MainActor.run { settings.biometricUnlockEnabled } },
            onAccountChanged: {
                await container.syncEngine.clearCredentialIdentitiesForAccountTransition()
            }
        )
        self.vault = VaultServiceAdapter(
            repository: container.vaultRepository,
            beforeAccess: { _ = await passkeyDrainer?.drain() }
        )

        #if os(iOS)
        // Register self as the singleton the BGTask handler reaches into (the handler is a
        // static closure registered at app `init`, which has no reference to this instance).
        AppEnvironment.sharedForBackground = self
        #endif
    }

    // MARK: - Lifecycle: auto-lock

    /// Called on entering the background. With `AutoLockTimeout.immediately` we lock right away;
    /// otherwise we stamp the time and apply the timeout on the next foreground.
    func handleEnterBackground() {
        backgroundedAt = Date()
        if settings.autoLockTimeout == .immediately {
            Task { await lock() }
        }
        // Close DB connections defensively on suspend (0xDEAD10CC protection is handled by the
        // store's WAL + busy_timeout; nothing extra needed here for the actor-owned handle).
    }

    /// Called on becoming active. If the auto-lock timeout has elapsed since backgrounding,
    /// lock the vault; otherwise leave it as-is.
    func handleBecomeActive() async {
        // Enforce the user's lock deadline before any refresh or other authenticated work.
        // A slow network request must never extend an expired in-memory key lifetime.
        await enforceBackgroundAutoLockIfNeeded()
        backgroundedAt = nil
        if await container.authRepository.session != nil {
            _ = try? await container.authRepository.refresh()
        }
        if await container.authRepository.isUnlocked() {
            _ = await performSync()
        }
    }

    private func enforceBackgroundAutoLockIfNeeded(now: Date = Date()) async {
        guard let backgroundedAt else { return }
        let timeout = settings.autoLockTimeout
        switch timeout {
        case .never:
            return
        case .immediately:
            await lock()
        default:
            let elapsed = now.timeIntervalSince(backgroundedAt)
            if elapsed >= Double(timeout.rawValue) {
                await lock()
            }
        }
    }

    /// Lock the vault: drops the in-memory user key (KeyVault) and clears the write-path
    /// encryptor via the AuthRepository.
    func lock() async {
        await container.authRepository.lock()
        authStateGeneration &+= 1
    }

    /// Seed an already-signed-in, locked session from the Keychain marker + encrypted account
    /// row. RootView is held on its loading surface until this finishes, so it cannot briefly
    /// route a returning user to login before the repository has restored its state.
    func seedSessionIfPresent() async {
        guard !didSeedSession, !isSeedingSession else { return }
        isSeedingSession = true
        defer {
            isSeedingSession = false
            didSeedSession = true
        }

        if let restoredServer = try? await container.authRepository.restoreSession() {
            settings.serverURL = restoredServer
            persistSettings()
            // A restored session intentionally has no bearer. Best-effort refresh makes
            // subsequent writes/sync usable while preserving offline unlock when unreachable.
            _ = try? await container.authRepository.refresh()
        }
        if await passkeyDrainer?.drain() == true {
            dataRevision &+= 1
        }
    }

    // MARK: - Background refresh (iOS: BGAppRefreshTask)

    /// Register the BGAppRefreshTask handler. Must be called from the app's `init` (before
    /// launch finishes). No-op off iOS.
    nonisolated static func registerBackgroundRefreshHandler(identifier: String) {
        #if os(iOS)
        BGTaskScheduler.shared.register(forTaskWithIdentifier: identifier, using: nil) { task in
            guard let refreshTask = task as? BGAppRefreshTask else { task.setTaskCompleted(success: false); return }
            nonisolated(unsafe) let bgTask = refreshTask
            let gate = BackgroundRefreshCompletionGate()
            bgTask.expirationHandler = {
                guard gate.expire() else { return }
                bgTask.setTaskCompleted(success: false)
            }
            let operation = Task {
                let success = await AppEnvironment.runBackgroundSync()
                guard gate.finish() else { return }
                AppEnvironment.scheduleBackgroundRefreshStatic(identifier: identifier)
                bgTask.setTaskCompleted(success: success)
            }
            gate.install(operation)
        }
        #endif
    }

    /// Submit the next background-refresh request (iOS). Call when entering background.
    func scheduleBackgroundRefresh(identifier: String) {
        #if os(iOS)
        AppEnvironment.scheduleBackgroundRefreshStatic(identifier: identifier)
        #endif
    }

    #if os(iOS)
    nonisolated static func scheduleBackgroundRefreshStatic(identifier: String) {
        let request = BGAppRefreshTaskRequest(identifier: identifier)
        request.earliestBeginDate = Date(timeIntervalSinceNow: 30 * 60) // ~30 min
        BGTaskScheduler.shared.submitTaskRequest(request) { _ in }
    }

    /// The BGTask handler runs the sync against the active account, if any.
    @MainActor
    private static var sharedForBackground: AppEnvironment?

    @MainActor
    static func runBackgroundSync() async -> Bool {
        guard let env = sharedForBackground else { return false }
        return await env.performSync()
    }
    #endif

    // MARK: - macOS background activity (NSBackgroundActivityScheduler)

    /// Start the periodic background sync on macOS (~30 min, utility QoS). No-op off macOS.
    func startMacBackgroundActivity() {
        #if os(macOS)
        guard macActivity == nil else { return }
        let activity = NSBackgroundActivityScheduler(identifier: "dev.moooyo.tessera.sync")
        activity.repeats = true
        activity.interval = 30 * 60
        activity.qualityOfService = .utility
        activity.schedule { [weak self] completion in
            Task { @MainActor in
                _ = await self?.performSync()
                completion(.finished)
            }
        }
        macActivity = activity
        #endif
    }

    /// Run a full sync + outbox flush against the active account. Returns false if there's no
    /// active account or the sync throws (background callers map this to task-failed).
    @discardableResult
    func performSync() async -> Bool {
        guard !isPerformingSync else { return false }
        isPerformingSync = true
        defer { isPerformingSync = false }
        // BGTaskScheduler/macOS activities can run long after the foreground transition
        // that normally enforces auto-lock. Apply the same deadline here before touching
        // the vault so a suspended app cannot retain keys past the configured timeout.
        await enforceBackgroundAutoLockIfNeeded()
        guard let accountID = await container.authRepository.session?.accountID,
              await container.authRepository.isUnlocked() else { return false }
        let imported = await passkeyDrainer?.drain() == true
        do {
            try await syncEngine.flushOutbox(accountID: accountID)
            _ = try await syncEngine.fullSync(accountID: accountID)
            dataRevision &+= 1
            return true
        } catch {
            if imported { dataRevision &+= 1 }
            return false
        }
    }

    // MARK: - Builders

    private static let clientVersion = "2024.1.0"

    /// The default SQLCipher DB URL inside the App Group container (so the extension shares it).
    private static func databaseURL(defaults: UserDefaults) -> URL {
        let fm = FileManager.default
        if let group = fm.containerURL(forSecurityApplicationGroupIdentifier: AppShared.appGroupID) {
            do {
                try fm.createDirectory(at: group, withIntermediateDirectories: true)
                return group.appendingPathComponent("tessera-vault.sqlite")
            } catch {
                #if !DEBUG
                fatalError("OpenVault App Group is not writable: \(error)")
                #endif
            }
        }
        // Unsigned simulator/local Debug builds do not receive App Group entitlements.
        #if !DEBUG
        fatalError("OpenVault App Group is unavailable")
        #else
        let fallback = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        try? fm.createDirectory(at: fallback, withIntermediateDirectories: true)
        return fallback.appendingPathComponent("tessera-vault.sqlite")
        #endif
    }

    private static func makeStore(keychain: KeychainBridge, defaults: UserDefaults) -> VaultStore {
        let url = databaseURL(defaults: defaults)
        let passphrase: Data
        do {
            passphrase = try loadOrCreatePassphrase()
        } catch {
            fatalError("Failed to load or create the vault store passphrase in the shared Keychain: \(error)")
        }
        // The store init can only fail on a genuinely unopenable file; in that (rare) case we
        // crash early rather than run with a half-built graph — the App Group container is a hard
        // requirement for a password manager.
        do {
            return try VaultStore(databaseURL: url, passphrase: passphrase)
        } catch {
            fatalError("Failed to open the vault store at \(url): \(error)")
        }
    }

    /// Load (or generate-and-store) the random 32-byte DB passphrase from the shared Keychain.
    ///
    /// The DB passphrase is a plain (non-biometry-gated) shared-access-group secret, so the
    /// underlying `SecItem` calls are fully synchronous. Reading it directly here — instead of
    /// hopping onto the `KeychainBridge` actor via a `Task.detached` + `DispatchSemaphore.wait()`
    /// bridge — avoids both the main-thread block / priority-inversion risk and the non-Sendable
    /// closure that strict concurrency rejects on Xcode 27.
    private static func loadOrCreatePassphrase() throws -> Data {
        let account = AppShared.KeychainAccount.databasePassphrase
        let accessGroup = AppShared.keychainAccessGroup

        if let existing = try keychainCopyPassphrase(account: account, accessGroup: accessGroup) {
            guard existing.count == 32 else {
                throw NSError(domain: "TesseraVaultStore", code: -2,
                              userInfo: [NSLocalizedDescriptionKey:
                                "The stored vault database passphrase has an invalid length."])
            }
            return existing
        }
        var fresh = Data(count: 32)
        let randomStatus = fresh.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!)
        }
        guard randomStatus == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(randomStatus))
        }
        return try keychainInsertPassphraseIfAbsent(
            fresh,
            account: account,
            accessGroup: accessGroup
        )
    }

    /// Synchronous read of a generic-password item from the shared access group.
    /// Mirrors `SystemKeychainItemStore.get` (whose body is itself synchronous `SecItem`).
    private static func keychainCopyPassphrase(account: String, accessGroup: String) throws -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: accessGroup,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            return item as? Data
        case errSecItemNotFound:
            return nil
        default:
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
    }

    /// Atomically insert the initial database key. A second app process can race the first
    /// launch; `errSecDuplicateItem` means the winner's key must be re-read and used. Never
    /// delete/replace this item, because doing so would permanently orphan an existing DB.
    private static func keychainInsertPassphraseIfAbsent(
        _ data: Data,
        account: String,
        accessGroup: String
    ) throws -> Data {
        let attributes: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: accessGroup,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        let status = SecItemAdd(attributes as CFDictionary, nil)
        if status == errSecSuccess { return data }
        if status == errSecDuplicateItem,
           let winner = try keychainCopyPassphrase(
               account: account,
               accessGroup: accessGroup
           ),
           winner.count == 32 {
            return winner
        }
        if status == errSecDuplicateItem {
            throw NSError(domain: "TesseraVaultStore", code: -2,
                          userInfo: [NSLocalizedDescriptionKey:
                            "The concurrently stored database passphrase is invalid."])
        } else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
    }

    private static func serverEnvironment(_ urlString: String) -> ServerEnvironment {
        if let env = ServerEnvironment(string: urlString) { return env }
        // Placeholder base until the user enters a server (the login flow validates + uses the
        // user-entered URL via the repository, so this default is never actually contacted).
        return ServerEnvironment(base: URL(string: "https://localhost")!)
    }

    private static func deviceMetadata(platform: Platform, defaults: UserDefaults) -> DeviceMetadata {
        let key = "tessera.deviceIdentifier"
        let identifier: String
        if let existing = defaults.string(forKey: key) {
            identifier = existing
        } else {
            identifier = UUID().uuidString
            defaults.set(identifier, forKey: key)
        }
        switch platform {
        case .iOS:
            return DeviceMetadata(type: DeviceMetadata.DeviceType.iOS,
                                  identifier: identifier, name: "Tessera iOS")
        case .macOS:
            return DeviceMetadata(type: DeviceMetadata.DeviceType.macOSDesktop,
                                  identifier: identifier, name: "Tessera macOS")
        }
    }

    private static func makeIdentityWriter() -> CredentialIdentityWriting {
        #if canImport(AuthenticationServices)
        return ASCredentialIdentityWriter()
        #else
        return NoopIdentityWriter()
        #endif
    }

    // MARK: - Settings persistence (App Group UserDefaults)

    private enum SettingsKeys {
        static let serverURL = "tessera.serverURL"
        static let autoLock = "tessera.autoLockTimeout"
        static let biometric = "tessera.biometricUnlockEnabled"
    }

    private static func loadSettings(from defaults: UserDefaults) -> SettingsModel {
        let server = defaults.string(forKey: SettingsKeys.serverURL) ?? AppShared.defaultServerURL
        let timeoutRaw = defaults.object(forKey: SettingsKeys.autoLock) as? Int
        let timeout = timeoutRaw.flatMap(AutoLockTimeout.init(rawValue:)) ?? .fiveMinutes
        let biometric = defaults.bool(forKey: SettingsKeys.biometric)
        return SettingsModel(serverURL: server, autoLockTimeout: timeout, biometricUnlockEnabled: biometric)
    }

    /// Persist the current settings back to App Group UserDefaults. Call from the Settings UI's
    /// save action (the scenes wire this to `onChange`).
    func persistSettings() {
        defaults.set(settings.serverURL, forKey: SettingsKeys.serverURL)
        defaults.set(settings.autoLockTimeout.rawValue, forKey: SettingsKeys.autoLock)
        defaults.set(settings.biometricUnlockEnabled, forKey: SettingsKeys.biometric)
    }

    /// Apply the toggle immediately. Enabling wraps the currently unlocked user key; if the
    /// vault is locked/unavailable, revert the UI instead of persisting a nonfunctional policy.
    func handleBiometricSettingChanged() {
        persistSettings()
        biometricSettingGeneration &+= 1
        let generation = biometricSettingGeneration
        let requested = settings.biometricUnlockEnabled
        Task { @MainActor in
            do {
                try await container.authRepository.setBiometricUnlockEnabled(requested)
            } catch {
                guard biometricSettingGeneration == generation else { return }
                settings.biometricUnlockEnabled = false
                persistSettings()
            }
        }
    }
}

#if os(iOS)
/// Coordinates BGTask expiration with asynchronous completion. Exactly one caller wins;
/// expiration also cancels the in-flight operation so it cannot reschedule after timeout.
private final class BackgroundRefreshCompletionGate: @unchecked Sendable {
    private let lock = NSLock()
    private var completed = false
    private var operation: Task<Void, Never>?

    func install(_ operation: Task<Void, Never>) {
        lock.lock()
        if completed {
            lock.unlock()
            operation.cancel()
        } else {
            self.operation = operation
            lock.unlock()
        }
    }

    func expire() -> Bool {
        lock.lock()
        guard !completed else { lock.unlock(); return false }
        completed = true
        let operation = self.operation
        self.operation = nil
        lock.unlock()
        operation?.cancel()
        return true
    }

    func finish() -> Bool {
        lock.lock()
        guard !completed else { lock.unlock(); return false }
        completed = true
        operation = nil
        lock.unlock()
        return true
    }
}
#endif

// MARK: - Fallback identity writer (when AuthenticationServices is unavailable)

@available(iOS 26.0, macOS 26.0, *)
private struct NoopIdentityWriter: CredentialIdentityWriting {
    func isEnabled() async -> Bool { false }
    func supportsIncremental() async -> Bool { false }
    func replaceAll(_ identities: [CredentialIdentity]) async {}
    func incremental(add: [CredentialIdentity], remove: [CredentialIdentity]) async {}
}
