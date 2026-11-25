// Xcode-only target. Not part of the SPM build.
//
// AppEnvironment — the production dependency-injection graph + app lifecycle glue, shared by
// the iOS and macOS app targets.
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
import PasskeyHandoff

#if os(macOS)
import AppKit
#endif

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
    let syncAccess: VaultSyncAccess
    /// The editable settings model, hydrated from App Group `UserDefaults`.
    let settings: SettingsModel

    #if os(macOS)
    let macSessionTimeoutSettings: MacSessionTimeoutModel
    let supportsMacTouchID: Bool
    private var macTouchIDStatusLease: AccountSessionLease?
    private var isChangingMacTouchID = false
    private var macTimeoutSignOutFailure: String?
    var macTimeoutSignOutFailed: Bool { macTimeoutSignOutFailure != nil }
    @ObservationIgnored private var macTimeoutMonitor: MacSessionTimeoutMonitor?
    #endif

    // MARK: - Concrete graph (retained for lifecycle: lock, sync, seed)

    private let container: ServiceContainer
    private let apiClient: APIClient
    private let platform: Platform
    private let defaults: UserDefaults
    private let passkeyDrainer: PasskeyRegistrationDrainer?

    /// Root views are created only after this flips to true, preventing their initial
    /// routing task from racing cold-session restoration.
    private(set) var didSeedSession = false
    private(set) var sessionRestoreFailed = false
    /// Recreates root/menu views after lifecycle auto-lock so plaintext held in view state
    /// is released and routing immediately resolves to the unlock screen.
    private(set) var authStateGeneration: UInt64 = 0
    /// Advances after background/foreground sync or passkey import changes local vault data.
    private(set) var dataRevision: UInt64 = 0
    private var isSeedingSession = false
    @ObservationIgnored private var lifecycleSyncTask: Task<Bool, Never>?
    private var biometricSettingGeneration: UInt64 = 0

    #if os(iOS)
    /// Timestamp of the last resign-active, used to apply the auto-lock timeout on return.
    private var backgroundedAt: Date?
    private var autoLockTask: Task<Void, Never>?
    private var pendingTimeoutAction: Task<Void, Never>?
    #endif

    #if os(macOS)
    var allowsWebsiteIconRequests: Bool {
        #if OPENVAULT_LOCAL_FIXTURE
        return false
        #else
        return true
        #endif
    }

    /// macOS uses an `NSBackgroundActivityScheduler` (no BGTaskScheduler).
    private var macActivity: NSBackgroundActivityScheduler?
    #endif

    // MARK: - Construction

    #if os(iOS)
    convenience init(platform: Platform) {
        do {
            try self.init(opening: platform)
        } catch {
            fatalError("Failed to open the encrypted vault store: \(error)")
        }
    }
    #endif

    init(opening platform: Platform) throws {
        self.platform = platform
        #if OPENVAULT_LOCAL_FIXTURE
        let defaults = UserDefaults.standard
        let sharedContainer: URL? = nil
        let fixture = try MacLocalFixture()
        let keychain = KeychainBridge.withoutSystemStorage()
        let store = fixture.store
        let networkSession = fixture.networkSession
        let requestAllowed: (@Sendable (URL) -> Bool)? = fixture.requestAllowed
        let usesLocalSessionStore = true
        #else
        #if OPENVAULT_LOCAL
        guard let service = Bundle.main.bundleIdentifier else { preconditionFailure("Missing app bundle identifier") }
        let defaults = UserDefaults.standard
        let sharedContainer: URL? = nil
        let keychain = KeychainBridge.withoutSystemStorage()
        let databaseKeys = DatabaseKeyStore.macLogin(service: service)
        let usesLocalSessionStore = true
        #else
        let defaults = UserDefaults(suiteName: AppShared.appGroupID) ?? .standard
        let sharedContainer = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: AppShared.appGroupID)
        let keychain = KeychainBridge(accessGroup: AppShared.keychainAccessGroup,
                                      service: "dev.moooyo.tessera")
        let databaseKeys = DatabaseKeyStore.shared(accessGroup: AppShared.keychainAccessGroup)
        let usesLocalSessionStore = false
        #endif
        let url = try Self.databaseURL(sharedContainer: sharedContainer)
        let passphrase = try databaseKeys.loadOrCreate(account: AppShared.KeychainAccount.databasePassphrase, for: url)
        let store = try VaultStore(databaseURL: url, passphrase: passphrase)
        let networkSession = URLSession.shared
        let requestAllowed: (@Sendable (URL) -> Bool)? = nil
        #endif
        self.defaults = defaults

        #if os(macOS) && OPENVAULT_LOCAL && !OPENVAULT_LOCAL_FIXTURE
        let localBiometrics: (any LocalBiometricKeyWrapping)? = SystemLocalBiometricKeyWrapper()
        #else
        let localBiometrics: (any LocalBiometricKeyWrapping)? = nil
        #endif

        // 1. Persisted settings (UserDefaults — NEVER keys/tokens).
        let settings = AppEnvironment.loadSettings(from: defaults)
        self.settings = settings
        #if os(macOS)
        self.macSessionTimeoutSettings = MacSessionTimeoutModel(defaults: defaults)
        self.supportsMacTouchID = !usesLocalSessionStore || localBiometrics != nil
        #endif

        // 2. Stable device metadata (a per-install UUID persisted in the App Group).
        let device = AppEnvironment.deviceMetadata(platform: platform, defaults: defaults)

        // 5. API client over the persisted server (a placeholder base when none is set yet —
        //    the login flow rebuilds the client implicitly via the repository's ServerEnvironment).
        let environment = AppEnvironment.serverEnvironment(settings.serverURL)
        let apiClient = APIClient(environment: environment,
                                  session: networkSession,
                                  device: device,
                                  clientVersion: AppEnvironment.clientVersion,
                                  requestAllowed: requestAllowed)
        self.apiClient = apiClient

        // 6. Compose the container + sync engine with the real AutoFill identity writer.
        let identityWriter = AppEnvironment.makeIdentityWriter()
        let container = ServiceContainer.makeDefault(apiClient: apiClient, store: store,
                                                     keychain: keychain,
                                                     identityStore: identityWriter,
                                                     usesLocalSessionStore: usesLocalSessionStore,
                                                     localBiometrics: localBiometrics)
        self.container = container

        let passkeyDrainer = sharedContainer.map {
            PasskeyRegistrationDrainer(
                handoff: PasskeyRegistrationHandoff(
                    directoryURL: $0.appendingPathComponent("passkey-handoff", isDirectory: true),
                    keychain: keychain
                ),
                auth: container.authRepository,
                vault: container.vaultRepository
            )
        }
        self.passkeyDrainer = passkeyDrainer

        // 7. VM-facing adapters (bind the per-session biometric policy from settings).
        let auth = AuthServiceAdapter(
            repository: container.authRepository,
            biometricPolicy: { await MainActor.run { !usesLocalSessionStore && settings.biometricUnlockEnabled } },
            onAccountChanged: {
                await container.syncEngine.clearCredentialIdentitiesForAccountTransition()
            }
        )
        self.auth = auth
        let syncAccess = VaultSyncAccess { await auth.transferSession() }
        self.syncAccess = syncAccess
        self.vault = VaultServiceAdapter(
            repository: container.vaultRepository,
            sendService: container.sendService,
            syncAccess: syncAccess,
            beforeAccess: { _ = await passkeyDrainer?.drain() }
        )

        #if os(iOS)
        // Register self as the singleton the BGTask handler reaches into (the handler is a
        // static closure registered at app `init`, which has no reference to this instance).
        AppEnvironment.sharedForBackground = self
        #endif
        #if os(macOS)
        macTimeoutMonitor = MacSessionTimeoutMonitor(settings: macSessionTimeoutSettings,
            sessionAt: { [repository = container.authRepository] eventTime, publicationFloor in
                await repository.sessionTimeoutLease(publishedBy: eventTime, after: publicationFloor)
            }, apply: { [weak self] lease, action, eventTime in
                await self?.applyMacTimeout(for: lease, action: action, systemEventAt: eventTime) ?? .superseded
            })
        macTimeoutMonitor?.startListening()
        #endif
    }

    // MARK: - Lifecycle: auto-lock

    /// Called on entering the background. With `AutoLockTimeout.immediately` we lock right away;
    /// otherwise we stamp the time and apply the timeout on the next foreground.
    func handleEnterBackground() {
        #if os(iOS)
        guard backgroundedAt == nil else { return }
        backgroundedAt = Date()
        let timeout = settings.autoLockTimeout
        guard timeout != .onSleep else { return }
        autoLockTask?.cancel()
        autoLockTask = Task { [weak self] in
            if timeout.rawValue > 0 {
                try? await Task.sleep(for: .seconds(timeout.rawValue))
            }
            guard !Task.isCancelled else { return }
            await self?.enforceBackgroundAutoLockIfNeeded()
        }
        #endif
    }

    /// Called on becoming active. If the auto-lock timeout has elapsed since backgrounding,
    /// lock the vault; otherwise leave it as-is.
    func handleBecomeActive() async {
        // Enforce the user's lock deadline before any refresh or other authenticated work.
        // A slow network request must never extend an expired in-memory key lifetime.
        #if os(macOS)
        await enforceMacTimeoutBeforeAccess()
        // Restored Mac sessions stay local until unlock; a locked vault cannot sync.
        guard didSeedSession, !macTimeoutSignOutFailed, await container.authRepository.isUnlocked() else { return }
        #else
        await enforceBackgroundAutoLockIfNeeded()
        autoLockTask?.cancel()
        backgroundedAt = nil
        #endif
        if await container.authRepository.session != nil {
            _ = try? await container.authRepository.refresh()
        }
        if await container.authRepository.isUnlocked() {
            _ = await performSync()
        }
    }

    #if os(iOS)
    private func enforceBackgroundAutoLockIfNeeded(now: Date = Date()) async {
        if let pendingTimeoutAction { await pendingTimeoutAction.value; return }
        guard let backgroundedAt else { return }
        let timeout = settings.autoLockTimeout
        switch timeout {
        case .onSleep:
            return
        case .immediately:
            await applyTimeoutAction()
        default:
            let elapsed = now.timeIntervalSince(backgroundedAt)
            if elapsed >= Double(timeout.rawValue) {
                await applyTimeoutAction()
            }
        }
    }

    private func applyTimeoutAction() async {
        if let pendingTimeoutAction { await pendingTimeoutAction.value; return }
        let operation = Task {
            guard await auth.hasSession() else { return }
            if defaults.bool(forKey: SettingsPreference.signsOutOnTimeout) {
                if await auth.logout() {
                    authStateGeneration &+= 1
                    return
                }
            }
            await lock()
        }
        pendingTimeoutAction = operation
        await operation.value
        pendingTimeoutAction = nil
        backgroundedAt = nil
    }
    #endif

    #if os(macOS)
    func authenticatedServerURL() async -> String? {
        await container.authRepository.session?.serverURL
    }

    func currentMacTimeoutLease() async -> AccountSessionLease? {
        await macTimeoutMonitor?.awaitSystemActions()
        return await container.authRepository.currentSessionLease()
    }

    func refreshMacTouchIDState(for lease: AccountSessionLease?) async -> Bool {
        #if OPENVAULT_LOCAL && !OPENVAULT_LOCAL_FIXTURE
        guard macTouchIDStatusLease != lease else { return true }
        guard !isChangingMacTouchID else { return false }
        let revision = biometricSettingGeneration
        let enabled = if lease != nil { await container.authRepository.localBiometricUnlockEnabled() } else { false }
        guard await container.authRepository.currentSessionLease() == lease,
              revision == biometricSettingGeneration, !isChangingMacTouchID else { return false }
        macTouchIDStatusLease = lease
        settings.biometricUnlockEnabled = enabled
        #endif
        return true
    }

    func setMacTouchIDEnabled(_ enabled: Bool, for lease: AccountSessionLease) async throws {
        guard supportsMacTouchID, !isChangingMacTouchID else { throw RepositoryError.authenticationFailed }
        isChangingMacTouchID = true
        biometricSettingGeneration &+= 1
        defer {
            biometricSettingGeneration &+= 1
            isChangingMacTouchID = false
        }
        try await container.authRepository.setBiometricUnlockEnabled(enabled, expectedSession: lease)
        guard await container.authRepository.currentSessionLease() == lease else { throw RepositoryError.notAuthenticated }
        settings.biometricUnlockEnabled = enabled
        #if OPENVAULT_LOCAL
        macTouchIDStatusLease = lease
        #else
        persistSettings()
        #endif
    }

    func enforceMacTimeoutBeforeAccess() async {
        await macTimeoutMonitor?.enforceBeforeAccess()
    }

    func updateMacTimeoutLease(_ unlocked: AccountSessionLease?, authenticated: AccountSessionLease?) {
        if unlocked != nil || authenticated?.accountID != macTimeoutSignOutFailure {
            macTimeoutSignOutFailure = nil
        }
        macSessionTimeoutSettings.selectAccount(authenticated?.accountID)
        macTimeoutMonitor?.observe(unlocked: unlocked, authenticated: authenticated)
    }

    private func applyMacTimeout(for lease: AccountSessionLease, action: MacSessionTimeoutAction,
                                 systemEventAt: ContinuousClock.Instant?) async -> SessionTimeoutResult {
        let result = await container.authRepository.expireSession(lease, logOut: action == .logOut,
                                                                  systemEventAt: systemEventAt)
        guard result != .superseded else { return result }
        lifecycleSyncTask?.cancel()
        authStateGeneration &+= 1
        if result == .logoutFailedLocked {
            macTimeoutSignOutFailure = lease.accountID
        } else if result == .loggedOut {
            macTimeoutSignOutFailure = nil
            await container.syncEngine.clearCredentialIdentitiesForAccountTransition()
        }
        return result
    }
    #endif

    /// Lock the vault: drops the in-memory user key (KeyVault) and clears the write-path
    /// encryptor via the AuthRepository.
    func lock() async {
        await container.authRepository.lock()
        authStateGeneration &+= 1
    }

    /// Restore the locked session and enforce local launch policy before routing. Do not
    /// wait for the server: the first sync after unlock can obtain a bearer if needed.
    func seedSessionIfPresent() async {
        guard !didSeedSession, !isSeedingSession else { return }
        isSeedingSession = true
        sessionRestoreFailed = false
        defer {
            isSeedingSession = false
            didSeedSession = true
        }

        let restoredServer: String?
        do { restoredServer = try await container.authRepository.restoreSession() }
        catch {
            #if OPENVAULT_LOCAL && !OPENVAULT_LOCAL_FIXTURE
            sessionRestoreFailed = true
            return
            #else
            restoredServer = nil
            #endif
        }
        if let restoredServer {
            settings.serverURL = restoredServer
            persistSettings()
            #if os(macOS)
            await macTimeoutMonitor?.enforceColdLaunchIfNeeded()
            #endif
        }
    }

    #if os(macOS)
    func retrySessionRestore() async {
        guard sessionRestoreFailed else { return }
        didSeedSession = false
        await seedSessionIfPresent()
    }
    #endif

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
        if let existing = lifecycleSyncTask { return await existing.value }
        let task = Task { await runLifecycleSync() }
        lifecycleSyncTask = task
        defer { lifecycleSyncTask = nil }
        return await withTaskCancellationHandler { await task.value } onCancel: { task.cancel() }
    }

    private func runLifecycleSync() async -> Bool {
        // BGTaskScheduler/macOS activities can run long after the foreground transition
        // that normally enforces auto-lock. Apply the same deadline here before touching
        // the vault so a suspended app cannot retain keys past the configured timeout.
        #if os(macOS)
        await enforceMacTimeoutBeforeAccess()
        guard didSeedSession, !macTimeoutSignOutFailed else { return false }
        #else
        await enforceBackgroundAutoLockIfNeeded()
        #endif
        return await VaultLifecycleSync.run(access: syncAccess, drain: { await self.passkeyDrainer?.drain() == true },
                                            synchronize: { [repository = container.vaultRepository] scope in
            try await repository.sync(expectedSession: scope)
        }, dataChanged: { self.dataRevision &+= 1 })
    }

    // MARK: - Builders

    private static let clientVersion = "2024.12.0"

    private static func databaseURL(sharedContainer: URL?) throws -> URL {
        let fm = FileManager.default
        #if OPENVAULT_LOCAL
        let directory = try fm.url(for: .applicationSupportDirectory, in: .userDomainMask,
                                   appropriateFor: nil, create: true)
        return directory.appendingPathComponent("tessera-vault.sqlite")
        #else
        if let group = sharedContainer {
            do {
                try fm.createDirectory(at: group, withIntermediateDirectories: true)
                return group.appendingPathComponent("tessera-vault.sqlite")
            } catch {
                #if !DEBUG
                throw error
                #endif
            }
        }
        // Unsigned simulator/local Debug builds do not receive App Group entitlements.
        #if !DEBUG
        throw CocoaError(.fileNoSuchFile, userInfo: [NSLocalizedDescriptionKey: "The OpenVault App Group is unavailable."])
        #else
        let fallback = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        try? fm.createDirectory(at: fallback, withIntermediateDirectories: true)
        return fallback.appendingPathComponent("tessera-vault.sqlite")
        #endif
        #endif
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
        #if canImport(AuthenticationServices) && !OPENVAULT_LOCAL
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
        var timeout = timeoutRaw.flatMap(AutoLockTimeout.init(rawValue:)) ?? .fiveMinutes
        #if os(iOS)
        if timeout == .onSleep { timeout = .fiveMinutes }
        #endif
        #if OPENVAULT_LOCAL
        let biometric = false
        #else
        let biometric = defaults.bool(forKey: SettingsKeys.biometric)
        #endif
        return SettingsModel(serverURL: server, autoLockTimeout: timeout, biometricUnlockEnabled: biometric)
    }

    /// Persist the current settings back to App Group UserDefaults. Call from the Settings UI's
    /// save action (the scenes wire this to `onChange`).
    func persistSettings() {
        defaults.set(settings.serverURL, forKey: SettingsKeys.serverURL)
        defaults.set(settings.autoLockTimeout.rawValue, forKey: SettingsKeys.autoLock)
        #if !OPENVAULT_LOCAL
        defaults.set(settings.biometricUnlockEnabled, forKey: SettingsKeys.biometric)
        #endif
    }

    #if os(iOS)
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
    #endif
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
