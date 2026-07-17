import SwiftUI
import UIShared
import DesignSystem
import AppShared

@available(iOS 27.0, *)
public struct SettingsView: View {
    private let auth: AuthService
    @State private var syncModel: SyncStatusModel
    @State private var settings: SettingsModel
    private let onSync: () async -> Void
    private let onAuthChange: () async -> Void

    @AppStorage(OpenVaultPreferenceKey.glassTint) private var glassTint = 0.68
    @AppStorage(OpenVaultPreferenceKey.theme) private var themeRawValue = OpenVaultTheme.system.rawValue
    @AppStorage(OpenVaultPreferenceKey.clipboardTimeout) private var clipboardTimeout = 30.0

    public init(auth: AuthService, syncModel: SyncStatusModel, settings: SettingsModel,
                onSync: @escaping () async -> Void,
                onAuthChange: @escaping () async -> Void) {
        self.auth = auth
        _syncModel = State(initialValue: syncModel)
        _settings = State(initialValue: settings)
        self.onSync = onSync
        self.onAuthChange = onAuthChange
    }

    public var body: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: Spacing.md) {
                accountCard

                groupTitle("安全")
                securityCard

                groupTitle("自动填充与同步")
                syncCard

                groupTitle("外观")
                appearanceCard

                Button(role: .destructive) {
                    Task { await auth.lock(); await onAuthChange() }
                } label: {
                    Label("立即锁定", systemImage: "lock.fill")
                        .font(.headline)
                        .frame(maxWidth: .infinity, minHeight: 50)
                }
                .buttonStyle(.bordered)
                .tint(Palette.danger)

                Text(versionText)
                    .font(.caption)
                    .foregroundStyle(Palette.tertiaryText)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, Spacing.lg)
            }
            .padding(Spacing.lg)
        }
        .background(Palette.groupedBackground)
        .scrollEdgeEffectStyle(.soft, for: .all)
        .navigationTitle("设置")
    }

    private var accountCard: some View {
        OpenVaultCard {
            HStack(spacing: Spacing.md) {
                Circle()
                    .fill(Palette.controlFill)
                    .frame(width: 52, height: 52)
                    .overlay { Text("O").font(.title3.weight(.semibold)) }
                VStack(alignment: .leading, spacing: Spacing.xxs) {
                    Text("OpenVault")
                        .font(.headline)
                    Text(serverDescription)
                        .font(.subheadline)
                        .foregroundStyle(Palette.secondaryText)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                Spacer()
                Image(systemName: settings.isServerURLValid ? "checkmark.circle.fill" : "exclamationmark.circle")
                    .foregroundStyle(settings.isServerURLValid ? Palette.success : Palette.warning)
                    .accessibilityHidden(true)
            }
        }
    }

    private var securityCard: some View {
        OpenVaultCard(padding: 0) {
            VStack(spacing: 0) {
                HStack(spacing: Spacing.md) {
                    SettingIconTile(systemImage: "faceid", color: Palette.accent)
                    Toggle(isOn: $settings.biometricUnlockEnabled) {
                        VStack(alignment: .leading, spacing: 1) {
                            Text("面容 ID / 触控 ID 解锁")
                            Text("更改将在下次登录时生效")
                                .font(.caption)
                                .foregroundStyle(Palette.secondaryText)
                        }
                    }
                }
                .padding(.horizontal, Spacing.lg)
                .frame(minHeight: 56)

                rowDivider

                HStack(spacing: Spacing.md) {
                    SettingIconTile(systemImage: "clock.fill", color: Palette.warning)
                    Text("自动锁定")
                    Spacer()
                    Picker("自动锁定", selection: $settings.autoLockTimeout) {
                        ForEach(settings.availableTimeouts, id: \.self) { timeout in
                            Text(timeoutLabel(timeout)).tag(timeout)
                        }
                    }
                    .labelsHidden()
                    .pickerStyle(.menu)
                }
                .padding(.horizontal, Spacing.lg)
                .frame(minHeight: 56)

                rowDivider

                HStack(spacing: Spacing.md) {
                    SettingIconTile(systemImage: "doc.on.doc.fill", color: Palette.purple)
                    Text("清空剪贴板")
                    Spacer()
                    Picker("清空剪贴板", selection: $clipboardTimeout) {
                        Text("永不").tag(0.0)
                        Text("30 秒").tag(30.0)
                        Text("1 分钟").tag(60.0)
                        Text("90 秒").tag(90.0)
                        Text("5 分钟").tag(300.0)
                    }
                    .labelsHidden()
                    .pickerStyle(.menu)
                }
                .padding(.horizontal, Spacing.lg)
                .frame(minHeight: 56)
            }
        }
    }

    private var syncCard: some View {
        OpenVaultCard(padding: 0) {
            VStack(spacing: 0) {
                HStack(spacing: Spacing.md) {
                    SettingIconTile(systemImage: "key.fill", color: Palette.success)
                    VStack(alignment: .leading, spacing: 1) {
                        Text("自动填充密码")
                        Text("由 iOS 密码与自动填充设置管理")
                            .font(.caption)
                            .foregroundStyle(Palette.secondaryText)
                    }
                    Spacer()
                    Text("系统管理")
                        .font(.caption)
                        .foregroundStyle(Palette.secondaryText)
                }
                .padding(.horizontal, Spacing.lg)
                .frame(minHeight: 60)

                rowDivider

                Button {
                    Task {
                        if await syncModel.sync() { await onSync() }
                    }
                } label: {
                    HStack(spacing: Spacing.md) {
                        SettingIconTile(systemImage: "arrow.triangle.2.circlepath", color: Palette.indigo)
                        VStack(alignment: .leading, spacing: 1) {
                            Text("立即同步")
                                .foregroundStyle(Palette.primaryText)
                            Text(syncDescription)
                                .font(.caption)
                                .foregroundStyle(Palette.secondaryText)
                        }
                        Spacer()
                        if syncModel.isSyncing { ProgressView().controlSize(.small) }
                    }
                    .padding(.horizontal, Spacing.lg)
                    .frame(minHeight: 60)
                }
                .buttonStyle(.plain)
                .disabled(syncModel.isSyncing)

                if let outcome = syncModel.lastOutcome, outcome.dropped > 0 {
                    rowDivider
                    Label("\(outcome.dropped) 个条目无法解码", systemImage: "exclamationmark.circle")
                        .font(.caption)
                        .foregroundStyle(Palette.warning)
                        .padding(.horizontal, Spacing.lg)
                        .frame(maxWidth: .infinity, minHeight: 44, alignment: .leading)
                }
            }
        }
    }

    private var appearanceCard: some View {
        OpenVaultCard(padding: 0) {
            VStack(spacing: 0) {
                VStack(alignment: .leading, spacing: Spacing.sm) {
                    HStack(spacing: Spacing.md) {
                        SettingIconTile(systemImage: "circle.lefthalf.filled", color: .black)
                        Text("液态玻璃")
                        Spacer()
                        Text(glassTint, format: .percent.precision(.fractionLength(0)))
                            .font(.subheadline)
                            .foregroundStyle(Palette.secondaryText)
                            .monospacedDigit()
                    }
                    Slider(value: $glassTint, in: 0...1)
                    HStack {
                        Text("清透")
                        Spacer()
                        Text("着色")
                    }
                    .font(.caption2)
                    .foregroundStyle(Palette.secondaryText)
                }
                .padding(Spacing.lg)

                rowDivider

                HStack(spacing: Spacing.md) {
                    SettingIconTile(systemImage: "paintpalette.fill", color: .gray)
                    Text("主题")
                    Spacer()
                    Picker("主题", selection: $themeRawValue) {
                        Text("跟随系统").tag(OpenVaultTheme.system.rawValue)
                        Text("浅色").tag(OpenVaultTheme.light.rawValue)
                        Text("深色").tag(OpenVaultTheme.dark.rawValue)
                    }
                    .labelsHidden()
                    .pickerStyle(.menu)
                }
                .padding(.horizontal, Spacing.lg)
                .frame(minHeight: 56)
            }
        }
    }

    private var rowDivider: some View {
        Divider().padding(.leading, 61)
    }

    private func groupTitle(_ title: String) -> some View {
        Text(title)
            .font(.subheadline)
            .foregroundStyle(Palette.secondaryText)
            .padding(.horizontal, Spacing.lg)
            .padding(.top, Spacing.sm)
    }

    private var serverDescription: String {
        guard settings.isServerURLValid, let url = URL(string: settings.serverURL) else {
            return "服务器尚未配置"
        }
        return url.host ?? settings.serverURL
    }

    private var syncDescription: String {
        if syncModel.isSyncing { return "正在同步…" }
        if let error = syncModel.errorMessage { return error }
        if let last = syncModel.lastSync {
            return "上次：\(last.formatted(.relative(presentation: .named)))"
        }
        return "尚未同步"
    }

    private var versionText: String {
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "1.0"
        let build = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "1"
        return "OpenVault \(version)（\(build)）"
    }

    private func timeoutLabel(_ timeout: AutoLockTimeout) -> String {
        switch timeout {
        case .immediately: "立即"
        case .oneMinute: "1 分钟后"
        case .fiveMinutes: "5 分钟后"
        case .fifteenMinutes: "15 分钟后"
        case .oneHour: "1 小时后"
        case .never: "永不"
        }
    }
}
