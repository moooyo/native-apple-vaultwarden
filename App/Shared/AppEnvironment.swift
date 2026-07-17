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
        self.syncEngine = SyncEngine(api: apiClient, store: store, keyVault: container.keyVault,
                                     identityStore: identityWriter)

        // 7. VM-facing adapters (bind the per-session biometric policy from settings).
        self.auth = AuthServiceAdapter(repository: container.authRepository,
                                       enableBiometrics: settings.biometricUnlockEnabled)
        self.vault = VaultServiceAdapter(repository: container.vaultRepository)

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
        defer { backgroundedAt = nil }
        guard let backgroundedAt else { return }
        let timeout = settings.autoLockTimeout
        switch timeout {
        case .never:
            return
        case .immediately:
            await lock()
        default:
            let elapsed = Date().timeIntervalSince(backgroundedAt)
            if elapsed >= Double(timeout.rawValue) {
                await lock()
            }
        }
    }

    /// Lock the vault: drops the in-memory user key (KeyVault) and clears the write-path
    /// encryptor via the AuthRepository.
    func lock() async {
        await container.authRepository.lock()
    }

    /// Seed an already-signed-in session at launch. The session lives in the AuthRepository's
    /// in-memory state; on a cold start it is `nil`, so this is a no-op for now (the persisted
    /// refresh token unlocks via `unlockWithBiometrics` / master password on the unlock screen).
    /// Kept as the explicit seam the blueprint calls for; a future restore path rehydrates the
    /// session from the store + refresh token here.
    func seedSessionIfPresent() async {
        // The persisted account row + refresh token enable the unlock screen; nothing to do
        // until a restore-session API lands. Documented seam (blueprint §G "Seed an already-
        // signed-in session if present").
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
        guard let accountID = await container.authRepository.session?.accountID else { return false }
        do {
            try await syncEngine.flushOutbox(accountID: accountID)
            _ = try await syncEngine.fullSync(accountID: accountID)
            return true
        } catch {
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
            #if DEBUG
            // Unsigned local/simulator builds have no shared Keychain entitlement.
            passphrase = Data(repeating: 0, count: 32)
            #else
            fatalError("OpenVault Keychain unavailable: \(error)")
            #endif
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
        let account = "tessera.db-passphrase"
        let accessGroup = AppShared.keychainAccessGroup

        if let existing = try keychainCopyPassphrase(account: account, accessGroup: accessGroup) {
            return existing
        }
        var fresh = Data(count: 32)
        let randomStatus = fresh.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!)
        }
        guard randomStatus == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(randomStatus))
        }
        try keychainStorePassphrase(fresh, account: account, accessGroup: accessGroup)
        return fresh
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

    /// Synchronous write of a generic-password item into the shared access group
    /// (`...WhenUnlockedThisDeviceOnly`, not biometry-gated). Mirrors `SystemKeychainItemStore.set`.
    private static func keychainStorePassphrase(_ data: Data, account: String, accessGroup: String) throws {
        // Replace any existing value.
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: accessGroup,
        ]
        SecItemDelete(deleteQuery as CFDictionary)

        let attributes: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: accessGroup,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        let status = SecItemAdd(attributes as CFDictionary, nil)
        guard status == errSecSuccess else {
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
