import AppShared
import AuthenticationServices
import DesignSystem
import SwiftUI
import SyncEngine
import UIShared

struct MacSettingsView: View {
    let auth: AuthService
    let syncModel: SyncStatusModel
    @Bindable var settings: SettingsModel
    let onSync: () async -> Void
    let onAuthChange: () async -> Void

    @AppStorage(SettingsPreference.showsMenuBar) private var showsMenuBar = true
    @AppStorage(SettingsPreference.locksOnSleep) private var locksOnSleep = true
    @AppStorage(AppShared.Preference.clipboardTimeout) private var clipboardSeconds = 60.0
    @State private var pane: MacSettingsPane
    @State private var email: String?
    @State private var kdfIterations: Int?
    @State private var confirmingLogout = false
    @State private var changingSession = false
    @State private var touchIDAvailable = false
    @State private var hasSystemError = false
    @State private var autofillEnabled: Bool?
    @Environment(\.appearsActive) private var appearsActive

    init(auth: AuthService, syncModel: SyncStatusModel, settings: SettingsModel, initialPane: MacSettingsPane = .general,
         onSync: @escaping () async -> Void, onAuthChange: @escaping () async -> Void) {
        self.auth = auth
        self.syncModel = syncModel
        self.settings = settings
        self.onSync = onSync
        _pane = State(initialValue: initialPane)
        self.onAuthChange = onAuthChange
    }

    var body: some View {
        Group {
            switch pane {
            case .general: general
            case .account: account
            case .security: security
            case .sync: sync
            case .autofill: autofill
            }
        }
        .formStyle(.grouped)
        .toggleStyle(.switch)
        .navigationTitle(pane.title)
        .toolbar {
            ForEach(MacSettingsPane.allCases, id: \.self) { destination in
                ToolbarItem(placement: .principal) {
                    Toggle(isOn: Binding(get: { pane == destination }, set: { _ in pane = destination })) {
                        Label(destination.title, systemImage: destination.symbol)
                    }
                    .toggleStyle(.button)
                    .help(destination.title)
                    .accessibilityAddTraits(pane == destination ? .isSelected : [])
                }
            }
        }
        .frame(width: 720)
        .frame(maxHeight: .infinity)
        .task {
            email = await auth.accountEmail()
            kdfIterations = await auth.accountKDFIterations()
        }
        #if !OPENVAULT_LOCAL
        .modifier(MacTouchIDAvailability(isAvailable: $touchIDAvailable))
        #endif
    }

    private var general: some View {
        Form {
            Section {
                Toggle("在菜单栏中显示 OpenVault", isOn: $showsMenuBar)
                Picker("清除剪贴板", selection: $clipboardSeconds) {
                    Text("30 秒后").tag(30.0)
                    Text("1 分钟后").tag(60.0)
                    Text("2 分钟后").tag(120.0)
                    Text("5 分钟后").tag(300.0)
                    Text("永不").tag(0.0)
                }
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
                        Text(displayName ?? "当前账户")
                            .font(.headline)
                        if let email { Text(email).foregroundStyle(.secondary) }
                    }
                }
                .accessibilityElement(children: .combine)
                .privacySensitive()
                if let host = settings.serverHost { LabeledContent("服务器", value: host) }
                if let kdfIterations { LabeledContent("密钥派生", value: "PBKDF2 · \(kdfIterations.formatted()) 次") }
            }
            Section {
                HStack {
                    Button("立即锁定") { changeSession(logout: false) }
                    Spacer()
                    Button("退出登录…", role: .destructive) { confirmingLogout = true }
                        .confirmationDialog("退出当前账户？", isPresented: $confirmingLogout, titleVisibility: .visible) {
                            Button("退出登录", role: .destructive) { changeSession(logout: true) }
                            Button("取消", role: .cancel) {}
                        } message: { Text("本机将移除登录凭据。再次访问保险库需要重新登录。") }
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
            Section {
                #if !OPENVAULT_LOCAL
                Toggle("使用触控 ID 解锁", isOn: $settings.biometricUnlockEnabled)
                    .disabled(!touchIDAvailable && !settings.biometricUnlockEnabled)
                #endif
                Picker("自动锁定", selection: $settings.autoLockTimeout) {
                    ForEach(settings.availableTimeouts + [.onSleep], id: \.self) { timeout in
                        Text(timeout.settingsLabel).tag(timeout)
                    }
                }
                Toggle("Mac 睡眠或会话切换时立即锁定", isOn: Binding(
                    get: { settings.autoLockTimeout == .onSleep || locksOnSleep },
                    set: { locksOnSleep = $0 }
                ))
                .disabled(settings.autoLockTimeout == .onSleep)
            }
        }
    }

    private var sync: some View {
        Form {
            Section {
                HStack {
                    if syncModel.isSyncing {
                        ProgressView().controlSize(.small)
                    } else {
                        Image(systemName: syncModel.errorMessage != nil ? "exclamationmark.circle" : "arrow.triangle.2.circlepath")
                            .foregroundStyle(.secondary).accessibilityHidden(true)
                    }
                    Text(syncModel.statusDescription)
                    Spacer()
                    Button("立即同步") { Task { if await syncModel.sync() { await onSync() } } }
                        .disabled(syncModel.isSyncing)
                }
                if let dropped = syncModel.lastOutcome?.dropped, dropped > 0 {
                    Label("\(dropped) 个条目无法解码", systemImage: "exclamationmark.triangle")
                }
            }
        }
    }

    private var autofill: some View {
        Form {
            Section {
                #if OPENVAULT_LOCAL
                LabeledContent("密码与通行密钥自动填充", value: "此独立版本不包含自动填充扩展")
                #else
                HStack {
                    Text("密码与通行密钥自动填充")
                    Spacer()
                    if let autofillEnabled {
                        Text(autofillEnabled ? "已启用" : "未启用").foregroundStyle(.secondary)
                    }
                    Button("打开系统设置…") {
                        Task {
                            do { try await ASSettingsHelper.openCredentialProviderAppSettings() }
                            catch { hasSystemError = true }
                        }
                    }
                    .alert("无法打开系统设置", isPresented: $hasSystemError) {
                        Button("好", role: .cancel) {}
                    } message: { Text("请前往“系统设置 › 通用 › 自动填充与密码”选择 OpenVault。") }
                }
                #endif
            } footer: {
                #if !OPENVAULT_LOCAL
                Text("在“系统设置 › 通用 › 自动填充与密码”里选择 OpenVault。")
                #endif
            }
        }
        #if !OPENVAULT_LOCAL
        .task(id: appearsActive) {
            guard appearsActive else { return }
            let enabled = await ASCredentialIdentityWriter().isEnabled()
            if !Task.isCancelled { autofillEnabled = enabled }
        }
        #endif
    }

    private func changeSession(logout: Bool) {
        guard !changingSession else { return }
        changingSession = true
        Task {
            if logout { await auth.logout() } else { await auth.lock() }
            await onAuthChange()
            changingSession = false
        }
    }
}

enum MacSettingsPane: Hashable, CaseIterable {
    case general, account, security, sync, autofill

    var title: String {
        switch self {
        case .general: "通用"
        case .account: "账户"
        case .security: "安全"
        case .sync: "同步"
        case .autofill: "自动填充"
        }
    }

    var symbol: String {
        switch self {
        case .general: "gearshape"
        case .account: "person.crop.circle"
        case .security: "lock.shield"
        case .sync: "arrow.triangle.2.circlepath"
        case .autofill: "key"
        }
    }
}
