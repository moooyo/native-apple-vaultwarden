import AppShared
import AuthenticationServices
import CryptoCore
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
    private let onClose: (() -> Void)?
    private let onSync: () async -> Void
    private let onAuthChange: () async -> Void

    @Environment(\.horizontalSizeClass) private var sizeClass
    @Environment(\.scenePhase) private var scenePhase
    @Environment(\.dynamicTypeSize) private var typeSize
    @Environment(\.tabBarPlacement) private var tabBarPlacement
    @Environment(\.colorSchemeContrast) private var contrast
    @Environment(\.vaultSecurityTools) private var securityTools
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
    @State private var recoveryReceipt: String?

    public init(auth: AuthService, vault: VaultService, model: VaultListModel,
                syncModel: SyncStatusModel, settings: SettingsModel,
                onClose: (() -> Void)? = nil,
                onSync: @escaping () async -> Void, onAuthChange: @escaping () async -> Void) {
        self.auth = auth
        self.vault = vault
        self.model = model
        self.syncModel = syncModel
        self.settings = settings
        self.onClose = onClose
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
        .task { await syncModel.refreshOutbox() }
        .onChange(of: syncModel.syncAttempt) { _, _ in recoveryReceipt = nil }
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
            Section { accountRows.listRowInsets(.vertical, Spacing.sm) }
            recoverySection
            Section("安全") { securityRows.listRowInsets(.vertical, Spacing.sm) }
            Section("自动填充") { autoFillRow.listRowInsets(.vertical, Spacing.sm) }
            Section("外观") { themePicker }
            Section("保险库") {
                NavigationLink {
                    VaultFoldersView(model: model, vault: vault)
                } label: {
                    HStack {
                        rowLabel(.folders)
                        Spacer()
                        if model.canPresentCounts {
                            Text("\(model.folders.count) 个").foregroundStyle(.secondary)
                        }
                    }
                }
                NavigationLink { transfer } label: { rowLabel(.transfer) }
            }
            .listRowInsets(.vertical, Spacing.sm)
            Section { accountActions } footer: {
                Text(versionText).frame(maxWidth: .infinity).padding(.top, Spacing.sm)
            }
        }
        .listStyle(.insetGrouped)
        .listSectionSpacing(6)
        .contentMargins(.horizontal, Spacing.lg, for: .scrollContent)
        .environment(\.defaultMinListRowHeight, LayoutMetric.phoneRowHeight)
        .navigationTitle("设置")
        .navigationBarTitleDisplayMode(.large)
        .accessibilityIdentifier("settings.sections")
    }

    private var regularSettings: some View {
        GeometryReader { geometry in
            HStack(spacing: 0) {
                NavigationStack {
                    List(SettingsCategory.allCases) { entry in
                        Button {
                            category = entry
                        } label: {
                            rowLabel(entry)
                                .foregroundStyle(category == entry ? (contrast == .increased ? Palette.contentBackground : Color.white) : .primary)
                                .padding(.horizontal, Spacing.md)
                                .padding(.vertical, Spacing.xs)
                                .frame(maxWidth: .infinity, minHeight: LayoutMetric.minimumTapTarget, alignment: .leading)
                                .background(category == entry ? (contrast == .increased ? Palette.primaryText : Color.accentColor) : .clear,
                                            in: .rect(cornerRadius: 10))
                                .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .accessibilityAddTraits(category == entry ? .isSelected : [])
                        .listRowInsets(EdgeInsets(top: 1, leading: 10, bottom: 1, trailing: 10))
                        .listRowSeparator(.hidden)
                        .listRowBackground(Color.clear)
                    }
                    .listStyle(.plain)
                    .scrollContentBackground(.hidden)
                    .background(Palette.contentBackground)
                    .navigationTitle("设置")
                    .navigationBarTitleDisplayMode(.large)
                    .toolbar {
                        if let onClose {
                            ToolbarItem(placement: .topBarLeading) {
                                Button("返回", systemImage: "chevron.backward", action: onClose)
                                    .accessibilityIdentifier("settings.back")
                            }
                        }
                    }
                }
                .frame(width: min(tabBarPlacement == .sidebar ? 300 : 340, geometry.size.width * 0.42))
                Divider()
                NavigationStack {
                    categoryDetail
                        .contentMargins(.horizontal, Spacing.xl, for: .scrollContent)
                        .navigationTitle(category.title)
                        .navigationBarTitleDisplayMode(.large)
                }
                .id(category)
                .frame(maxWidth: 600, maxHeight: .infinity)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(Palette.groupedBackground)
            }
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
                    recoverySection
                    Section { accountActions }
                case .security:
                    Section { securityRows } footer: {
                        if signsOutOnTimeout { Text("超时后需要重新登录才能访问保险库。") }
                    }
                case .autofill:
                    Section {
                        autoFillRow
                        Toggle(isOn: $copyCodeAfterFill) {
                            settingsLabel("填充后拷贝验证码", systemImage: "number", color: .teal)
                        }
                    } footer: { Text("在“设置 › 通用 › 自动填充与密码”中选择 OpenVault。") }
                case .appearance:
                    Section { themePicker }
                    Section {
                        Toggle("显示条目图标", isOn: $showsItemIcons)
                        Toggle("列表中显示用户名", isOn: $showsUsernames)
                    }
                case .about:
                    Section {
                        VStack(spacing: Spacing.xs) {
                            OpenVaultMark(size: 84).padding(.bottom, Spacing.sm)
                            Text("OpenVault").font(Typography.sectionTitle)
                            Text("版本 \(buildDescription)").font(.subheadline).foregroundStyle(.secondary)
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, Spacing.sm)
                        .listRowBackground(Color.clear)
                    }
                    Section {
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
            .listSectionSpacing(20)
            .environment(\.defaultMinListRowHeight, 52)
        }
    }

    @ViewBuilder private var recoverySection: some View {
        if SyncRecoverySection.isNeeded(model: syncModel, receipt: recoveryReceipt) {
            SyncRecoverySection(model: syncModel, receipt: $recoveryReceipt)
        }
    }

    @ViewBuilder private var accountRows: some View {
        let displayName = syncModel.accountDisplayName(email: email, serverURL: settings.serverURL)
        let layout = typeSize.isAccessibilitySize ? AnyLayout(VStackLayout(alignment: .leading, spacing: Spacing.sm))
            : AnyLayout(HStackLayout(spacing: 14))
        layout {
            accountAvatar(name: displayName)
            VStack(alignment: .leading, spacing: Spacing.xxs) {
                Text(displayName ?? "当前账户").font(.headline)
                if let email { Text(email).font(.subheadline).foregroundStyle(.secondary) }
                if let host = settings.serverHost { Text(host).font(.footnote).foregroundStyle(.secondary) }
            }
        }
        .accessibilityElement(children: .combine)
        .privacySensitive()
        .padding(.vertical, sizeClass == .regular ? Spacing.xs : Spacing.xxs)
        if let kdfIterations, KDF.isPBKDF2BelowRecommendation(iterations: kdfIterations) {
            Label("Your PBKDF2 iteration count is below the recommended \(KDF.recommendedPBKDF2Iterations). Review the key derivation settings in your web vault.",
                  systemImage: "exclamationmark.triangle")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        syncRow
        if let dropped = syncModel.lastOutcome?.dropped, dropped > 0 {
            Label("\(dropped) 个条目无法解码", systemImage: "exclamationmark.triangle").font(.footnote)
        }
    }

    private func accountAvatar(name: String?) -> some View {
        let words = name?.split(whereSeparator: \.isWhitespace) ?? []
        let first = words.first?.first ?? email?.first
        let last = words.count > 1 ? words.last?.first : nil
        let initials = String([first, last].compactMap { $0 }).localizedUppercase
        return ZStack {
            Circle().fill(Palette.secondaryText)
            if initials.isEmpty {
                Image(systemName: "person.fill")
            } else {
                Text(initials).lineLimit(1)
            }
        }
        .font(.system(size: 21, weight: .semibold))
        .foregroundStyle(Palette.contentBackground)
        .frame(width: sizeClass == .regular ? 56 : 54, height: sizeClass == .regular ? 56 : 54)
        .accessibilityHidden(true)
    }

    private var syncRow: some View {
        let layout = typeSize.isAccessibilitySize ? AnyLayout(VStackLayout(alignment: .leading)) : AnyLayout(HStackLayout())
        return layout {
            HStack(spacing: Spacing.sm) {
                if syncModel.isSyncing || syncModel.isResolving {
                    ProgressView().controlSize(.small)
                } else {
                    Circle().fill(syncColor).frame(width: 8, height: 8).accessibilityHidden(true)
                }
                Text(syncModel.statusDescription)
                    .font(.subheadline)
                    .accessibilityIdentifier("sync.status")
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            Button("立即同步", systemImage: "arrow.triangle.2.circlepath") {
                Task { if await syncModel.sync() { await onSync() } }
            }
            .buttonStyle(.bordered)
            .disabled(syncModel.isSyncing || syncModel.isResolving)
        }
    }

    private var syncColor: Color {
        if syncModel.errorMessage != nil || syncModel.hasOutstandingChanges || syncModel.isOutboxStatusUnavailable { return .orange }
        return syncModel.lastSync == nil ? .secondary : .green
    }

    @ViewBuilder private var securityRows: some View {
        if let securityTools { VaultSecurityActions(auth: auth, tools: securityTools, isUnlocked: true) }
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
            HStack(spacing: Spacing.sm) {
                settingsLabel("密码与通行密钥填充", systemImage: "key.fill", color: .indigo)
                Spacer(minLength: Spacing.xs)
                if !typeSize.isAccessibilitySize {
                    Text("系统设置").font(.subheadline).foregroundStyle(.secondary)
                }
                Image(systemName: "arrow.up.forward.square").foregroundStyle(.secondary).accessibilityHidden(true)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityHint("打开系统自动填充设置")
    }

    @ViewBuilder private var themePicker: some View {
        if typeSize.isAccessibilitySize {
            themeOptions.pickerStyle(.menu)
        } else {
            themeOptions
                .pickerStyle(.segmented)
                .listRowInsets(EdgeInsets())
                .listRowBackground(Color.clear)
        }
    }

    private var themeOptions: some View {
        Picker("外观", selection: $theme) {
            Text("跟随系统").tag(OpenVaultTheme.system)
            Text("浅色").tag(OpenVaultTheme.light)
            Text("深色").tag(OpenVaultTheme.dark)
        }
    }

    @ViewBuilder private var accountActions: some View {
        Button { changeSession(logout: false) } label: {
            Text("立即锁定").frame(maxWidth: .infinity, minHeight: 44).contentShape(Rectangle())
        }
        .alignmentGuide(.listRowSeparatorLeading) { _ in 0 }
        .listRowInsets(EdgeInsets(top: 0, leading: Spacing.lg, bottom: 0, trailing: Spacing.lg))
        .disabled(changingSession)
        Button(role: .destructive) { confirmingLogout = true } label: {
            Text("退出登录").frame(maxWidth: .infinity, minHeight: 44).contentShape(Rectangle())
        }
            .alignmentGuide(.listRowSeparatorLeading) { _ in 0 }
            .listRowInsets(EdgeInsets(top: 0, leading: Spacing.lg, bottom: 0, trailing: Spacing.lg))
            .disabled(changingSession)
            .confirmationDialog("退出当前账户？", isPresented: $confirmingLogout, titleVisibility: .visible) {
                Button("退出登录", role: .destructive) { changeSession(logout: true) }
                Button("取消", role: .cancel) {}
            } message: { Text("本机将移除登录凭据和生成历史。再次访问保险库需要重新登录。") }
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
        "OpenVault \(buildDescription)"
    }

    private var buildDescription: String {
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "–"
        let build = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "–"
        return "\(version)（\(build)）"
    }

    private func rowLabel(_ entry: SettingsCategory) -> some View {
        settingsLabel(entry.title, systemImage: entry.symbol,
                      color: entry == .transfer && sizeClass != .regular ? .gray : entry.color)
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
