import CryptoCore
import DesignSystem
import SwiftUI
import UIShared

struct MacSettingsView: View {
    let auth: AuthService
    let syncModel: SyncStatusModel
    let settings: SettingsModel
    let timeoutSettings: MacSessionTimeoutModel
    let isVaultUnlocked: Bool
    let onSetTouchID: ((Bool) async throws -> Void)?
    let onSync: () async -> Void
    let onAuthChange: () async -> Void
    let onLock: () async -> Void
    let onSignOutIntent: () -> Void
    let onSignOutFailure: () -> Void
    let onOpenVault: () -> Void

    @AppStorage(SettingsPreference.showsMenuBar) private var showsMenuBar = true
    @AppStorage(SettingsPreference.showsWebsiteIcons) private var showsWebsiteIcons = SettingsPreference.defaultShowsWebsiteIcons
    @State private var pane: MacSettingsPane
    @State private var email: String?
    @State private var kdfIterations: Int?
    @State private var confirmingLogout = false
    @State private var changingSession = false
    @State private var touchIDAvailable = false
    @State private var changingTouchID = false
    @State private var touchIDChangeFailed = false
    @State private var recoveryReceipt: String?
    @Environment(\.vaultSecurityTools) private var securityTools
    @Environment(\.locale) private var locale

    init(auth: AuthService, syncModel: SyncStatusModel, settings: SettingsModel,
         timeoutSettings: MacSessionTimeoutModel = MacSessionTimeoutModel(), isVaultUnlocked: Bool = true,
         initialPane: MacSettingsPane = .general, onSetTouchID: ((Bool) async throws -> Void)? = nil,
         onSync: @escaping () async -> Void, onAuthChange: @escaping () async -> Void,
         onLock: (() async -> Void)? = nil, onSignOutIntent: @escaping () -> Void = {},
         onSignOutFailure: @escaping () -> Void = {}, onOpenVault: @escaping () -> Void = {}) {
        self.auth = auth
        self.syncModel = syncModel
        self.settings = settings
        self.timeoutSettings = timeoutSettings
        self.isVaultUnlocked = isVaultUnlocked
        self.onSetTouchID = onSetTouchID
        self.onSync = onSync
        _pane = State(initialValue: initialPane)
        self.onAuthChange = onAuthChange
        self.onLock = onLock ?? { await auth.lock() }
        self.onSignOutIntent = onSignOutIntent
        self.onSignOutFailure = onSignOutFailure
        self.onOpenVault = onOpenVault
    }

    var body: some View {
        TabView(selection: $pane) {
            ForEach(MacSettingsPane.allCases, id: \.self) { destination in
                Tab(value: destination) {
                    paneContent(destination)
                } label: {
                    Label { destination.title } icon: { Image(systemName: destination.symbol) }
                }
            }
        }
        .formStyle(.grouped)
        .toggleStyle(.switch)
        .navigationTitle(pane.localizedTitle(in: locale))
        .frame(width: 720)
        .frame(minHeight: 242, maxHeight: .infinity)
        .task(id: isVaultUnlocked) {
            email = nil
            kdfIterations = nil
            guard isVaultUnlocked else { return }
            let accountEmail = await auth.accountEmail()
            let accountIterations = await auth.accountKDFIterations()
            guard !Task.isCancelled else { return }
            email = accountEmail
            kdfIterations = accountIterations
        }
        .modifier(MacTouchIDAvailability(isAvailable: $touchIDAvailable, enabled: isVaultUnlocked && onSetTouchID != nil))
    }

    @ViewBuilder
    private func paneContent(_ destination: MacSettingsPane) -> some View {
        if destination.requiresUnlockedVault && !isVaultUnlocked {
            ContentUnavailableView {
                Label {
                    Text("Vault Is Locked", tableName: "MacSettings")
                } icon: {
                    Image(systemName: "lock")
                }
            } description: {
                Text("Open OpenVault to change account settings.", tableName: "MacSettings")
            } actions: {
                Button(action: onOpenVault) { Text("Open OpenVault", tableName: "MacSettings") }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            switch destination {
            case .general: general
            case .preferences: preferences
            case .account: account
            case .security: security
            case .sync: sync
            case .ssh: ssh
            }
        }
    }

    private var general: some View {
        Form {
            Section {
                MacKeepRunningSetting()
                Toggle(isOn: $showsMenuBar) {
                    Text("Show OpenVault in the menu bar", tableName: "MacSettings")
                }
                .accessibilityIdentifier("settings.menu-bar")
                MacLaunchAtLoginSetting()
            } header: {
                Text("Window and Startup", tableName: "MacSettings")
            }
            Section {
                MacThemeSetting()
                MacLanguageSetting()
                MacQuickCopySettings()
            } header: {
                Text("Appearance", tableName: "MacSettings")
            }
        }
    }

    private var preferences: some View {
        Form {
            Section { MacClipboardBehaviorSettings() }
            Section {
                Toggle("Load website icons", isOn: $showsWebsiteIcons)
                    .accessibilityIdentifier("settings.website-icons")
            } footer: {
                Text("Sends the website’s domain to your Vaultwarden server.")
            }
        }
    }

    private var account: some View {
        let displayName = syncModel.accountDisplayName(email: email, serverURL: settings.serverURL)
        return Form {
            Section {
                HStack(spacing: Spacing.md) {
                    accountAvatar(name: displayName)
                    VStack(alignment: .leading, spacing: Spacing.xxs) {
                        Group {
                            if let displayName { Text(displayName) }
                            else { Text("Current Account", tableName: "MacSettings") }
                        }.font(.headline)
                        if let email { Text(email).foregroundStyle(.secondary) }
                    }
                }
                .accessibilityElement(children: .combine)
                .privacySensitive()
                if let host = settings.serverHost {
                    LabeledContent { Text(host) } label: { Text("Server", tableName: "MacSettings") }
                }
                if let kdfIterations {
                    LabeledContent {
                        Text("PBKDF2 · \(kdfIterations) iterations", tableName: "MacSettings")
                    } label: {
                        Text("Key Derivation", tableName: "MacSettings")
                    }
                    if KDF.isPBKDF2BelowRecommendation(iterations: kdfIterations) {
                        Label("Your PBKDF2 iteration count is below the recommended \(KDF.recommendedPBKDF2Iterations). Review the key derivation settings in your web vault.",
                              systemImage: "exclamationmark.triangle")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            Section {
                HStack {
                    Button { changeSession(logout: false) } label: { Text("Lock Now", tableName: "MacSettings") }
                    Spacer()
                    Button(role: .destructive) { onSignOutIntent(); confirmingLogout = true } label: { Text("Sign Out…", tableName: "MacSettings") }
                        .confirmationDialog(Text("Sign out of this account?", tableName: "MacSettings"), isPresented: $confirmingLogout, titleVisibility: .visible) {
                            Button(role: .destructive) { changeSession(logout: true) } label: { Text("Sign Out", tableName: "MacSettings") }
                            Button("Cancel", role: .cancel) {}
                        } message: {
                            Text("OpenVault removes the saved session from this Mac. Sign in again to access your vault.", tableName: "MacSettings")
                        }
                }
                .disabled(changingSession)
            }
        }
    }

    private func accountAvatar(name: String?) -> some View {
        let words = name?.split(whereSeparator: \.isWhitespace) ?? []
        let first = words.first?.first ?? email?.first
        let last = words.count > 1 ? words.last?.first : nil
        let initials = String([first, last].compactMap { $0 }).localizedUppercase
        return ZStack {
            Circle().fill(Palette.secondaryText)
            if initials.isEmpty { Image(systemName: "person.fill") }
            else { Text(initials) }
        }
        .font(.system(size: 16, weight: .semibold))
        .foregroundStyle(Palette.contentBackground)
        .frame(width: 40, height: 40)
        .accessibilityHidden(true)
    }

    private var security: some View {
        Form {
            if let securityTools {
                Section("Account Security") { VaultSecurityActions(auth: auth, tools: securityTools, isUnlocked: isVaultUnlocked) }
            }
            MacSessionTimeoutSettings(settings: timeoutSettings)
            if onSetTouchID != nil {
                Section {
                    Toggle(isOn: Binding(get: { settings.biometricUnlockEnabled }, set: changeTouchID)) {
                        Text("Unlock with Touch ID", tableName: "MacSettings")
                    }
                    .disabled(changingTouchID || (!touchIDAvailable && !settings.biometricUnlockEnabled))
                    .accessibilityIdentifier("settings.touch-id")
                    if touchIDChangeFailed {
                        Label {
                            Text("Could Not Change Touch ID", tableName: "MacSettings")
                        } icon: {
                            Image(systemName: "exclamationmark.triangle")
                        }
                        .foregroundStyle(.red)
                        .accessibilityIdentifier("settings.touch-id.error")
                    }
                }
            }
        }
    }

    private func changeTouchID(_ enabled: Bool) {
        guard let onSetTouchID, !changingTouchID, enabled != settings.biometricUnlockEnabled else { return }
        changingTouchID = true
        touchIDChangeFailed = false
        Task {
            defer { changingTouchID = false }
            do { try await onSetTouchID(enabled) }
            catch { touchIDChangeFailed = true }
        }
    }

    private var sync: some View {
        Form {
            Section {
                HStack {
                    if syncModel.isSyncing || syncModel.isResolving {
                        ProgressView().controlSize(.small)
                    } else {
                        let needsAttention = syncModel.errorMessage != nil || syncModel.hasOutstandingChanges || syncModel.isOutboxStatusUnavailable
                        Image(systemName: needsAttention ? "exclamationmark.circle" : "arrow.triangle.2.circlepath")
                            .foregroundStyle(.secondary).accessibilityHidden(true)
                    }
                    Text(MacLocalization.syncStatusDescription(syncModel, locale: locale))
                        .accessibilityIdentifier("sync.status")
                    Spacer()
                    Button {
                        Task { if await syncModel.sync() { await onSync() } }
                    } label: {
                        Text("Sync Now", tableName: "MacSettings")
                    }
                    .buttonStyle(.bordered)
                    .disabled(syncModel.isSyncing || syncModel.isResolving)
                    .accessibilityIdentifier("sync.retry")
                }
                if let dropped = syncModel.lastOutcome?.dropped, dropped > 0 {
                    Label {
                        Text("Items that could not be decoded: \(dropped)", tableName: "MacSettings")
                    } icon: {
                        Image(systemName: "exclamationmark.triangle")
                    }
                }
            }
            if SyncRecoverySection.isNeeded(model: syncModel, receipt: recoveryReceipt) {
                SyncRecoverySection(model: syncModel, receipt: $recoveryReceipt)
            }
        }
        .task(id: syncModel.syncAccess?.backgroundOutboxRevision) { await syncModel.refreshOutbox() }
        .onChange(of: syncModel.syncAttempt) { _, _ in recoveryReceipt = nil }
    }

    private var ssh: some View {
        Form { MacSSHAgentSettingsSection() }
    }

    private func changeSession(logout: Bool) {
        guard !changingSession else { return }
        changingSession = true
        Task {
            defer { changingSession = false }
            if logout {
                onSignOutIntent()
                guard await auth.logout() else { onSignOutFailure(); return }
            } else {
                await onLock()
            }
            await onAuthChange()
        }
    }
}

enum MacSettingsPane: String, CaseIterable {
    case general, preferences, security, account, sync, ssh

    private var titleKey: String {
        switch self {
        case .general: "General"
        case .preferences: "Preferences"
        case .security: "Security"
        case .account: "Account"
        case .sync: "Sync"
        case .ssh: "SSH"
        }
    }

    var title: Text { Text(LocalizedStringKey(titleKey), tableName: "MacSettings") }

    func localizedTitle(in locale: Locale) -> String {
        MacLocalization.text(titleKey, table: "MacSettings", locale: locale)
    }

    var requiresUnlockedVault: Bool { self == .account || self == .security || self == .sync }

    var symbol: String {
        switch self {
        case .general: "gearshape"
        case .preferences: "slider.horizontal.3"
        case .account: "person.crop.circle"
        case .security: "lock.shield"
        case .sync: "arrow.triangle.2.circlepath"
        case .ssh: "terminal"
        }
    }
}
