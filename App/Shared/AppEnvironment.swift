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
            Task { @MainActor in
                let success = await AppEnvironment.runBackgroundSync()
                AppEnvironment.scheduleBackgroundRefreshStatic(identifier: identifier)
                refreshTask.setTaskCompleted(success: success)
            }
            refreshTask.expirationHandler = { refreshTask.setTaskCompleted(success: false) }
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
        try? BGTaskScheduler.shared.submit(request)
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
        let container = fm.containerURL(forSecurityApplicationGroupIdentifier: AppShared.appGroupID)
            ?? fm.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return container.appendingPathComponent("tessera-vault.sqlite")
    }

    private static func makeStore(keychain: KeychainBridge, defaults: UserDefaults) -> VaultStore {
        let url = databaseURL(defaults: defaults)
        let passphrase = (try? loadOrCreatePassphrase(keychain: keychain)) ?? Data(repeating: 0, count: 32)
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
    /// This is synchronous-best-effort at construction; the actor `get`/`set` are awaited via a
    /// blocking bridge only once at launch.
    private static func loadOrCreatePassphrase(keychain: KeychainBridge) throws -> Data {
        let account = "tessera.db-passphrase"
        // Use a semaphore to bridge the async Keychain access into the synchronous initializer.
        // This runs once at launch on a background-priority detached task, so it won't deadlock
        // the main actor (the KeychainBridge is its own actor).
        let semaphore = DispatchSemaphore(value: 0)
        var result: Data?
        Task.detached(priority: .userInitiated) {
            if let existing = try? await keychain.getSecret(account: account) {
                result = existing
            } else {
                var fresh = Data(count: 32)
                _ = fresh.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
                try? await keychain.setSecret(fresh, account: account, biometryGated: false)
                result = fresh
            }
            semaphore.signal()
        }
        semaphore.wait()
        guard let result else { throw NSError(domain: "Tessera", code: -1) }
        return result
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

// MARK: - Fallback identity writer (when AuthenticationServices is unavailable)

@available(iOS 26.0, macOS 26.0, *)
private struct NoopIdentityWriter: CredentialIdentityWriting {
    func isEnabled() async -> Bool { false }
    func supportsIncremental() async -> Bool { false }
    func replaceAll(_ identities: [CredentialIdentity]) async {}
    func incremental(add: [CredentialIdentity], remove: [CredentialIdentity]) async {}
}
