// Xcode-only target. Not part of the SPM build.
//
// AppEnvironment composes the production services and governs session restoration,
// locking, and background sync. macOS uses a private sandbox and login Keychain;
// iOS shares its encrypted vault and Keychain access with the AutoFill extension.

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

#if os(iOS)
import BackgroundTasks
import PasskeyHandoff
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
    let vaultHealthReportVault: VaultService
    let accountTwoFactor: AccountTwoFactorManagement
    let emergencyAccess: EmergencyAccessRepository
    let deviceApproval: DeviceApprovalRepository
    var vaultSecurityTools: VaultSecurityTools {
        VaultSecurityTools(localVault: vaultHealthReportVault, twoFactor: accountTwoFactor,
                           emergencyAccess: emergencyAccess, deviceApproval: deviceApproval, generation: authStateGeneration)
    }
    let syncAccess: VaultSyncAccess
    /// The editable settings model, hydrated from the platform’s defaults.
    let settings: SettingsModel

    #if os(macOS)
    let macSessionTimeoutSettings: MacSessionTimeoutModel
    let supportsMacTouchID: Bool
    private var macTouchIDStatusLease: AccountSessionLease?
    private var isChangingMacTouchID = false
    private var macTimeoutSignOutFailure: String?
    var macTimeoutSignOutFailed: Bool { macTimeoutSignOutFailure != nil }
    @ObservationIgnored private var macTimeoutMonitor: MacSessionTimeoutMonitor?
    @ObservationIgnored private let macLockedRelaunch = MacLockedRelaunch.shared
    #endif

    // MARK: - Concrete graph (retained for lifecycle: lock, sync, seed)

    private let container: ServiceContainer
    private let defaults: UserDefaults
    #if os(iOS)
    private let passkeyDrainer: PasskeyRegistrationDrainer?
    #endif

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
        #if OPENVAULT_MAC_FIXTURE
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
        #if os(macOS)
        let defaults = UserDefaults.standard
        let keychain = KeychainBridge.withoutSystemStorage()
        let identityWriter = NoopIdentityWriter()
        let autoFillAccess: AutoFillAccessGate? = nil
        let usesLocalSessionStore = true
        #if !OPENVAULT_MAC_FIXTURE
        let localBiometrics: (any LocalBiometricKeyWrapping)? = SystemLocalBiometricKeyWrapper()
        #else
        let localBiometrics: (any LocalBiometricKeyWrapping)? = nil
        #endif
        #else
        let defaults = UserDefaults(suiteName: AppShared.appGroupID) ?? .standard
        let sharedContainer = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: AppShared.appGroupID)
        let keychain = KeychainBridge(accessGroup: AppShared.keychainAccessGroup,
                                      service: "dev.moooyo.tessera")
        let identityWriter = ASCredentialIdentityWriter()
        let autoFillAccess = sharedContainer.map { AutoFillAccessGate(url: $0.appendingPathComponent("autofill-owner")) }
        let usesLocalSessionStore = false
        let localBiometrics: (any LocalBiometricKeyWrapping)? = nil
        #endif

        #if OPENVAULT_MAC_FIXTURE
        let fixture = try MacLocalFixture()
        let store = fixture.store
        let networkSession = fixture.networkSession
        let requestAllowed: (@Sendable (URL) -> Bool)? = fixture.requestAllowed
        #else
        #if os(macOS)
        guard let service = Bundle.main.bundleIdentifier else { preconditionFailure("Missing app bundle identifier") }
        let databaseKeys = DatabaseKeyStore.macLogin(service: service)
        let url = try Self.databaseURL()
        #else
        let databaseKeys = DatabaseKeyStore.shared(accessGroup: AppShared.keychainAccessGroup)
        let url = try Self.databaseURL(sharedContainer: sharedContainer)
        #endif
        let passphrase = try databaseKeys.loadOrCreate(account: AppShared.KeychainAccount.databasePassphrase, for: url)
        let store = try VaultStore(databaseURL: url, passphrase: passphrase)
        let networkConfiguration = URLSessionConfiguration.ephemeral
        networkConfiguration.urlCache = nil
        networkConfiguration.httpCookieStorage = nil
        networkConfiguration.urlCredentialStorage = nil
        let networkSession = URLSession(configuration: networkConfiguration)
        let requestAllowed: (@Sendable (URL) -> Bool)? = nil
        #endif
        self.defaults = defaults

        let settings = AppEnvironment.loadSettings(from: defaults)
        self.settings = settings
        #if os(macOS)
        self.macSessionTimeoutSettings = MacSessionTimeoutModel(defaults: defaults)
        self.supportsMacTouchID = localBiometrics != nil
        #endif

        let device = AppEnvironment.deviceMetadata(platform: platform, defaults: defaults)
        let environment = AppEnvironment.serverEnvironment(settings.serverURL)
        let apiClient = APIClient(environment: environment,
                                  session: networkSession,
                                  device: device,
                                  clientVersion: AppEnvironment.clientVersion,
                                  requestAllowed: requestAllowed)
        let container = ServiceContainer.makeDefault(apiClient: apiClient, store: store,
                                                     keychain: keychain,
                                                     identityStore: identityWriter,
                                                     usesLocalSessionStore: usesLocalSessionStore,
                                                     localBiometrics: localBiometrics, autoFillAccess: autoFillAccess)
        self.container = container
        self.vaultHealthReportVault = VaultServiceAdapter(repository: container.vaultRepository)
        self.accountTwoFactor = AccountTwoFactorManagement(api: apiClient, auth: container.authRepository)
        self.emergencyAccess = EmergencyAccessRepository(auth: container.authRepository, api: apiClient,
            keyVault: container.keyVault, store: store, fingerprintWords: GeneratorModel.standardDicewareWords)
        self.deviceApproval = DeviceApprovalRepository(api: apiClient, auth: container.authRepository,
            keyVault: container.keyVault, fingerprintWords: GeneratorModel.standardDicewareWords)

        #if os(iOS)
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

        let auth = AuthServiceAdapter(
            repository: container.authRepository,
            biometricPolicy: { await MainActor.run { settings.biometricUnlockEnabled } },
            securityKeyAuthorizer: WebAuthnSecurityKey.authorize(challenge:environment:),
            allowsServer: { apiClient.allowsServer($0) },
            onLock: { await container.syncEngine.clearCredentialIdentitiesForAccountTransition() },
            onAccountChanged: {
                await container.syncEngine.clearCredentialIdentitiesForAccountTransition()
                if let lease = await container.authRepository.unlockedSessionLease() {
                    let generation = await container.syncEngine.identityGenerationLease()
                    guard await container.authRepository.unlockedSessionLease() == lease else { return }
                    await container.syncEngine.refreshCredentialIdentities(accountID: lease.accountID,
                                                                           expectedGeneration: generation)
                }
            }
        )
        #else
        let auth = AuthServiceAdapter(repository: container.authRepository, biometricPolicy: { false },
                                      allowsServer: { apiClient.allowsServer($0) })
        #endif
        self.auth = auth
        let syncAccess = VaultSyncAccess { await auth.transferSession() }
        self.syncAccess = syncAccess
        self.vault = VaultServiceAdapter(
            repository: container.vaultRepository,
            sendService: container.sendService,
            syncAccess: syncAccess,
            beforeAccess: {
                #if os(iOS)
                _ = await passkeyDrainer?.drain()
                #endif
            }
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
        #if !OPENVAULT_MAC_FIXTURE
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
        macTouchIDStatusLease = lease
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
        let activity = macLockedRelaunch.activityGeneration
        let unlocked = await container.authRepository.unlockedSessionLease()
        let result = await container.authRepository.expireSession(lease, logOut: action == .logOut,
                                                                  systemEventAt: systemEventAt)
        guard result != .superseded else { return result }
        lifecycleSyncTask?.cancel()
        authStateGeneration &+= 1
        if result == .logoutFailedLocked {
            macTimeoutSignOutFailure = lease.accountID
        } else if result == .loggedOut {
            macTimeoutSignOutFailure = nil
            cancelMacLockedRelaunch()
        } else if let unlocked, unlocked.accountID == lease.accountID {
            await scheduleMacRelaunch(after: unlocked, activity: activity)
        }
        return result
    }

    func cancelMacLockedRelaunch() { macLockedRelaunch.cancel() }

    private func scheduleMacRelaunch(after unlocked: AccountSessionLease, activity: UInt64) async {
        #if !OPENVAULT_MAC_FIXTURE
        let locked = AccountSessionLease(accountID: unlocked.accountID, generation: unlocked.generation &+ 1)
        guard didSeedSession, await container.authRepository.currentSessionLease() == locked,
              macLockedRelaunch.activityGeneration == activity,
              macSessionTimeoutSettings.policy(for: locked.accountID).action(for: .coldLaunch) == nil else { return }
        macLockedRelaunch.schedule { [weak self] in
            guard let self, self.macSessionTimeoutSettings.policy(for: locked.accountID).action(for: .coldLaunch) == nil,
                  await self.container.authRepository.currentSessionLease() == locked else { return false }
            return await self.container.authRepository.unlockedSessionLease() == nil
        }
        #endif
    }
    #endif

    func lock() async {
        #if os(macOS)
        let activity = macLockedRelaunch.activityGeneration
        let unlocked = await container.authRepository.unlockedSessionLease()
        #endif
        lifecycleSyncTask?.cancel()
        await container.authRepository.lock()
        authStateGeneration &+= 1
        #if os(macOS)
        if let unlocked { await scheduleMacRelaunch(after: unlocked, activity: activity) }
        #else
        await container.syncEngine.clearCredentialIdentitiesForAccountTransition()
        #endif
    }

    /// Restore the locked session and enforce local launch policy before routing. Do not
    /// wait for the server: the first sync after unlock can obtain a bearer if needed.
    func seedSessionIfPresent() async {
        guard !didSeedSession, !isSeedingSession else { return }
        isSeedingSession = true
        sessionRestoreFailed = false
        #if os(iOS)
        await container.syncEngine.clearCredentialIdentitiesForAccountTransition()
        #endif
        defer {
            isSeedingSession = false
            didSeedSession = true
        }

        let restoredServer: String?
        do { restoredServer = try await container.authRepository.restoreSession() }
        catch {
            #if os(macOS) && !OPENVAULT_MAC_FIXTURE
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
        return await VaultLifecycleSync.run(
            access: syncAccess,
            drain: {
                #if os(iOS)
                await self.passkeyDrainer?.drain() == true
                #else
                false
                #endif
            },
            synchronize: { [repository = container.vaultRepository] scope in
                try await repository.sync(expectedSession: scope)
            },
            dataChanged: { self.dataRevision &+= 1 }
        )
    }

    // MARK: - Builders

    private static let clientVersion = "2024.12.0"

    #if os(macOS)
    private static func databaseURL() throws -> URL {
        let directory = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask,
                                                    appropriateFor: nil, create: true)
        return directory.appendingPathComponent("tessera-vault.sqlite")
    }
    #else
    private static func databaseURL(sharedContainer: URL?) throws -> URL {
        let fm = FileManager.default
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
    }
    #endif

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

    // MARK: - Settings persistence

    private enum SettingsKeys {
        static let serverURL = "tessera.serverURL"
        static let autoLock = "tessera.autoLockTimeout"
        #if os(iOS)
        static let biometric = "tessera.biometricUnlockEnabled"
        #endif
    }

    private static func loadSettings(from defaults: UserDefaults) -> SettingsModel {
        let server = defaults.string(forKey: SettingsKeys.serverURL) ?? AppShared.defaultServerURL
        let timeoutRaw = defaults.object(forKey: SettingsKeys.autoLock) as? Int
        let configuredTimeout = timeoutRaw.flatMap(AutoLockTimeout.init(rawValue:)) ?? .fiveMinutes
        #if os(iOS)
        let timeout = configuredTimeout == .onSleep ? .fiveMinutes : configuredTimeout
        let biometric = defaults.bool(forKey: SettingsKeys.biometric)
        #else
        let timeout = configuredTimeout
        let biometric = false
        #endif
        return SettingsModel(serverURL: server, autoLockTimeout: timeout, biometricUnlockEnabled: biometric)
    }

    /// Persist platform preferences. The Mac Touch ID policy lives in the encrypted session.
    func persistSettings() {
        defaults.set(settings.serverURL, forKey: SettingsKeys.serverURL)
        defaults.set(settings.autoLockTimeout.rawValue, forKey: SettingsKeys.autoLock)
        #if os(iOS)
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
