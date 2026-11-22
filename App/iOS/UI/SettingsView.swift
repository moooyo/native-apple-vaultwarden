import AppShared
import AuthenticationServices
import DesignSystem
import LocalAuthentication
import SwiftUI
import UIShared

@available(iOS 27.0, *)
public struct SettingsView: View {
    private let auth: AuthService
    private let vault: VaultService
    private let model: VaultListModel
    private let syncModel: SyncStatusModel
    @Bindable private var settings: SettingsModel
    private let onSync: () async -> Void
    private let onAuthChange: () async -> Void

    @Environment(\.horizontalSizeClass) private var sizeClass
    @Environment(\.scenePhase) private var scenePhase
    @Environment(\.dynamicTypeSize) private var typeSize
    @AppStorage(OpenVaultPreferenceKey.theme) private var theme = OpenVaultTheme.system
    @AppStorage(AppShared.Preference.clipboardTimeout, store: AppShared.Preference.defaults) private var clipboardSeconds = 60.0
    @AppStorage(AppShared.Preference.copyCodeAfterFill, store: AppShared.Preference.defaults) private var copyCodeAfterFill = false
    @AppStorage(SettingsPreference.signsOutOnTimeout, store: AppShared.Preference.defaults) private var signsOutOnTimeout = false
    @AppStorage(SettingsPreference.showsItemIcons) private var showsItemIcons = true
    @AppStorage(SettingsPreference.showsUsernames) private var showsUsernames = true
    @State private var category = SettingsCategory.account
    @State private var email: String?
    @State private var kdfIterations: Int?
    @State private var biometry: LABiometryType = .none
    @State private var biometricAvailable = false
    @State private var confirmingLogout = false
    @State private var confirmingTimeoutLogout = false
    @State private var hasSystemError = false
    @State private var changingSession = false

    public init(auth: AuthService, vault: VaultService, model: VaultListModel,
                syncModel: SyncStatusModel, settings: SettingsModel,
                onSync: @escaping () async -> Void, onAuthChange: @escaping () async -> Void) {
        self.auth = auth
        self.vault = vault
        self.model = model
        self.syncModel = syncModel
        self.settings = settings
        self.onSync = onSync
        self.onAuthChange = onAuthChange
    }

    public var body: some View {
        Group {
            if sizeClass == .regular {
                regularSettings
            } else {
                compactSettings
            }
        }
        .task {
            email = await auth.accountEmail()
            kdfIterations = await auth.accountKDFIterations()
        }
        .onChange(of: scenePhase, initial: true) { _, phase in
            guard phase == .active else { return }
            let context = LAContext()
            biometricAvailable = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
            biometry = context.biometryType
        }
        .alert("无法打开系统设置", isPresented: $hasSystemError) {
            Button("好", role: .cancel) {}
        } message: {
            Text("请前往“设置 › 通用 › 自动填充与密码”选择 OpenVault。")
        }
    }

    private var compactSettings: some View {
        List {
            Section { accountRows }
            Section("安全") { securityRows }
            Section("自动填充") { autoFillRow }
            Section("外观") { themePicker }
            Section("保险库") {
                NavigationLink {
                    VaultFoldersView(model: model, vault: vault)
                } label: {
                    HStack {
                        rowLabel(.folders)
                        Spacer()
                        Text("\(model.folders.count) 个").foregroundStyle(.secondary)
                    }
                }
                NavigationLink { transfer } label: { rowLabel(.transfer) }
            }
            Section { accountActions } footer: {
                Text(versionText).frame(maxWidth: .infinity).padding(.top, Spacing.sm)
            }
        }
        .listStyle(.insetGrouped)
        .environment(\.defaultMinListRowHeight, 52)
        .navigationTitle("设置")
        .navigationBarTitleDisplayMode(.large)
        .accessibilityIdentifier("settings.sections")
    }

    private var regularSettings: some View {
        HStack(spacing: 0) {
            NavigationStack {
                List(SettingsCategory.allCases, selection: Binding<SettingsCategory?>($category)) { entry in
                    rowLabel(entry).tag(entry)
                }
                .listStyle(.sidebar)
                .navigationTitle("设置")
                .navigationBarTitleDisplayMode(.large)
            }
            .frame(minWidth: 215, idealWidth: 300, maxWidth: 340)
            Divider()
            NavigationStack {
                categoryDetail
                    .navigationTitle(category.title)
                    .navigationBarTitleDisplayMode(.large)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .id(category)
        }
    }

    @ViewBuilder private var categoryDetail: some View {
        switch category {
        case .folders:
            VaultFoldersView(model: model, vault: vault)
        case .transfer:
            transfer
        default:
            List {
                switch category {
                case .account:
                    Section { accountRows }
                    Section { accountActions }
                case .security:
                    Section { securityRows } footer: {
                        if signsOutOnTimeout { Text("超时后需要重新登录才能访问保险库。") }
                    }
                case .autofill:
                    Section {
                        autoFillRow
                        Toggle("填充后拷贝验证码", isOn: $copyCodeAfterFill)
                    } footer: { Text("在“设置 › 通用 › 自动填充与密码”中选择 OpenVault。") }
                case .appearance:
                    Section { themePicker }
                    Section {
                        Toggle("显示条目图标", isOn: $showsItemIcons)
                        Toggle("列表中显示用户名", isOn: $showsUsernames)
                    }
                case .about:
                    Section {
                        HStack(spacing: Spacing.md) {
                            OpenVaultMark(size: 48)
                            VStack(alignment: .leading) {
                                Text("OpenVault").font(.headline)
                                Text(versionText).font(.footnote).foregroundStyle(.secondary)
                            }
                        }
                        if let host = settings.serverHost { LabeledContent("服务器", value: host) }
                        if let kdfIterations { LabeledContent("密钥派生", value: "PBKDF2 · \(kdfIterations.formatted()) 次") }
                        if let source = URL(string: "https://github.com/moooyo/native-apple-vaultwarden") {
                            Link("源代码", destination: source)
                            Link("报告问题", destination: source.appending(path: "issues"))
                        }
                    }
                case .folders, .transfer:
                    EmptyView()
                }
            }
            .listStyle(.insetGrouped)
            .environment(\.defaultMinListRowHeight, 52)
            .frame(maxWidth: 600)
            .frame(maxWidth: .infinity)
            .background(Palette.groupedBackground)
        }
    }

    @ViewBuilder private var accountRows: some View {
        HStack(spacing: Spacing.lg) {
            OpenVaultMark(size: 54)
            VStack(alignment: .leading, spacing: Spacing.xxs) {
                Text(syncModel.accountDisplayName(email: email, serverURL: settings.serverURL) ?? "当前账户")
                    .font(.headline)
                if let email { Text(email).font(.subheadline).foregroundStyle(.secondary) }
                if let host = settings.serverHost { Text(host).font(.footnote).foregroundStyle(.secondary) }
            }
        }
        .accessibilityElement(children: .combine)
        .padding(.vertical, Spacing.xs)
        syncRow
        if let dropped = syncModel.lastOutcome?.dropped, dropped > 0 {
            Label("\(dropped) 个条目无法解码", systemImage: "exclamationmark.triangle").font(.footnote)
        }
    }

    private var syncRow: some View {
        let layout = typeSize.isAccessibilitySize ? AnyLayout(VStackLayout(alignment: .leading)) : AnyLayout(HStackLayout())
        return layout {
            HStack(spacing: Spacing.sm) {
                if syncModel.isSyncing {
                    ProgressView().controlSize(.small)
                } else {
                    Circle().fill(syncColor).frame(width: 8, height: 8).accessibilityHidden(true)
                }
                Text(syncModel.statusDescription).font(.subheadline)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            Button("立即同步", systemImage: "arrow.triangle.2.circlepath") {
                Task { if await syncModel.sync() { await onSync() } }
            }
            .buttonStyle(.bordered)
            .disabled(syncModel.isSyncing)
        }
    }

    private var syncColor: Color {
        if syncModel.errorMessage != nil { return .orange }
        return syncModel.lastSync == nil ? .secondary : .green
    }

    @ViewBuilder private var securityRows: some View {
        Toggle(isOn: $settings.biometricUnlockEnabled) {
            settingsLabel(biometry == .faceID ? "面容 ID 解锁" : biometry == .touchID ? "触控 ID 解锁" : "生物识别解锁",
                          systemImage: biometry == .touchID ? "touchid" : "faceid", color: .green)
        }
        .disabled(!biometricAvailable && !settings.biometricUnlockEnabled)
        Picker(selection: $settings.autoLockTimeout) {
            ForEach(settings.availableTimeouts, id: \.self) { Text($0.settingsLabel).tag($0) }
        } label: {
            settingsLabel("自动锁定", systemImage: "lock.fill", color: .orange)
        }
        if sizeClass == .regular || signsOutOnTimeout {
            Picker(selection: Binding(get: { signsOutOnTimeout }, set: { choice in
                if choice { confirmingTimeoutLogout = true } else { signsOutOnTimeout = false }
            })) {
                Text("锁定保险库").tag(false)
                Text("退出登录").tag(true)
            } label: {
                settingsLabel("超时后的操作", systemImage: "lock.rotation", color: .red)
            }
            .confirmationDialog("超时后退出登录？", isPresented: $confirmingTimeoutLogout, titleVisibility: .visible) {
                Button("超时后退出登录", role: .destructive) { signsOutOnTimeout = true }
                Button("取消", role: .cancel) {}
            } message: { Text("下次打开保险库时需要重新登录，而不能仅使用生物识别解锁。") }
        }
        Picker(selection: $clipboardSeconds) {
            Text("30 秒").tag(30.0)
            Text("1 分钟").tag(60.0)
            Text("2 分钟").tag(120.0)
            Text("永不").tag(0.0)
        } label: {
            settingsLabel("清空剪贴板", systemImage: "doc.on.doc.fill", color: .blue)
        }
    }

    private var autoFillRow: some View {
        Button {
            Task {
                do { try await ASSettingsHelper.openCredentialProviderAppSettings() }
                catch { hasSystemError = true }
            }
        } label: {
            HStack {
                settingsLabel("密码与通行密钥填充", systemImage: "key.fill", color: .indigo)
                Spacer()
                Image(systemName: "arrow.up.forward.square").foregroundStyle(.secondary).accessibilityHidden(true)
            }
        }
        .buttonStyle(.plain)
        .accessibilityHint("打开系统自动填充设置")
    }

    private var themePicker: some View {
        Picker("外观", selection: $theme) {
            Text("跟随系统").tag(OpenVaultTheme.system)
            Text("浅色").tag(OpenVaultTheme.light)
            Text("深色").tag(OpenVaultTheme.dark)
        }
        .pickerStyle(.segmented)
    }

    @ViewBuilder private var accountActions: some View {
        Button("立即锁定") { changeSession(logout: false) }
            .frame(maxWidth: .infinity).disabled(changingSession)
        Button("退出登录", role: .destructive) { confirmingLogout = true }
            .frame(maxWidth: .infinity).disabled(changingSession)
            .confirmationDialog("退出当前账户？", isPresented: $confirmingLogout, titleVisibility: .visible) {
                Button("退出登录", role: .destructive) { changeSession(logout: true) }
                Button("取消", role: .cancel) {}
            } message: { Text("本机将移除登录凭据。再次访问保险库需要重新登录。") }
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

    private var transfer: some View {
        VaultTransferView(auth: auth, vault: vault, onImported: onSync)
    }

    private var versionText: String {
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "–"
        let build = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "–"
        return "OpenVault \(version)（\(build)）"
    }

    private func rowLabel(_ entry: SettingsCategory) -> some View {
        settingsLabel(entry.title, systemImage: entry.symbol, color: entry.color)
    }

    private func settingsLabel(_ title: String, systemImage: String, color: Color) -> some View {
        HStack(spacing: Spacing.md) {
            SettingIconTile(systemImage: systemImage, color: color)
            Text(title)
        }
    }
}

private enum SettingsCategory: String, CaseIterable, Identifiable {
    case account, security, autofill, appearance, folders, transfer, about
    var id: Self { self }

    var title: String {
        switch self {
        case .account: "账户"
        case .security: "安全"
        case .autofill: "自动填充"
        case .appearance: "外观"
        case .folders: "文件夹"
        case .transfer: "导入与导出"
        case .about: "关于"
        }
    }

    var symbol: String {
        switch self {
        case .account: "person.crop.square.fill"
        case .security: "lock.fill"
        case .autofill: "key.fill"
        case .appearance: "eye.fill"
        case .folders: "folder.fill"
        case .transfer: "archivebox.fill"
        case .about: "info.circle.fill"
        }
    }

    var color: Color {
        switch self {
        case .account, .about: .gray
        case .security: .green
        case .autofill: .indigo
        case .appearance: .blue
        case .folders: .cyan
        case .transfer: .orange
        }
    }
}
