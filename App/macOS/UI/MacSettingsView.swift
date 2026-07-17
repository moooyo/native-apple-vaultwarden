import SwiftUI
import UIShared
import DesignSystem
import AppShared

@available(macOS 27.0, *)
struct MacSettingsView: View {
    private let auth: AuthService
    @State private var syncModel: SyncStatusModel
    @State private var settings: SettingsModel
    private let onSync: () async -> Void
    private let onAuthChange: () async -> Void

    @AppStorage(OpenVaultPreferenceKey.glassTint) private var glassTint = 0.68
    @AppStorage(OpenVaultPreferenceKey.clipboardTimeout) private var clipboardTimeout = 60.0

    init(auth: AuthService, syncModel: SyncStatusModel, settings: SettingsModel,
         onSync: @escaping () async -> Void,
         onAuthChange: @escaping () async -> Void) {
        self.auth = auth
        _syncModel = State(initialValue: syncModel)
        _settings = State(initialValue: settings)
        self.onSync = onSync
        self.onAuthChange = onAuthChange
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                header
                accountCard
                sectionTitle("安全")
                securityCard
                sectionTitle("自动填充与同步")
                syncCard
                sectionTitle("外观")
                appearanceCard
                lockCard
                Text("OpenVault · 与 Vaultwarden 兼容")
                    .font(.system(size: 11.5))
                    .foregroundStyle(.white.opacity(0.36))
                    .frame(maxWidth: .infinity)
                    .padding(.top, 4)
            }
            .padding(24)
            .frame(maxWidth: 760, alignment: .leading)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(MacOpenVaultStyle.detail)
    }

    private var header: some View {
        HStack(spacing: 13) {
            Image(systemName: "gearshape")
                .font(.system(size: 21, weight: .medium))
                .foregroundStyle(.white)
                .frame(width: 50, height: 50)
                .background(Color.gray.opacity(0.62), in: Circle())
            VStack(alignment: .leading, spacing: 2) {
                Text("设置")
                    .font(.system(size: 20, weight: .bold))
                    .foregroundStyle(.white)
                Text("安全、同步与 OpenVault 外观")
                    .font(.system(size: 12))
                    .foregroundStyle(MacOpenVaultStyle.secondary)
            }
        }
    }

    private var accountCard: some View {
        settingsCard {
            HStack(spacing: 12) {
                OpenVaultMark(size: 42)
                VStack(alignment: .leading, spacing: 2) {
                    Text("OpenVault")
                        .font(.system(size: 15, weight: .semibold))
                        .foregroundStyle(.white.opacity(0.94))
                    Text(settings.serverURL.nilIfBlank ?? "尚未设置服务器")
                        .font(.system(size: 12))
                        .foregroundStyle(.white.opacity(0.46))
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                Spacer()
                Image(systemName: "lock.shield")
                    .foregroundStyle(MacOpenVaultStyle.selectedBlue)
            }
            .padding(15)
        }
    }

    private var securityCard: some View {
        settingsCard {
            VStack(spacing: 0) {
                settingRow(icon: "lock", color: .orange, title: "自动锁定") {
                    Picker("自动锁定", selection: $settings.autoLockTimeout) {
                        ForEach(settings.availableTimeouts, id: \.self) { timeout in
                            Text(label(for: timeout)).tag(timeout)
                        }
                    }
                    .labelsHidden()
                    .frame(width: 150)
                }
                rowDivider
                settingRow(icon: "touchid", color: .blue, title: "使用触控 ID") {
                    Toggle("", isOn: $settings.biometricUnlockEnabled)
                        .labelsHidden()
                }
                rowDivider
                settingRow(icon: "doc.on.clipboard", color: .purple, title: "清除剪贴板") {
                    Picker("清除剪贴板", selection: $clipboardTimeout) {
                        Text("永不").tag(0.0)
                        Text("30 秒").tag(30.0)
                        Text("1 分钟").tag(60.0)
                        Text("2 分钟").tag(120.0)
                        Text("5 分钟").tag(300.0)
                    }
                    .labelsHidden()
                    .frame(width: 120)
                }
            }
        }
    }

    private var syncCard: some View {
        settingsCard {
            VStack(spacing: 0) {
                settingRow(icon: "key.fill", color: .green, title: "密码自动填充") {
                    Text("系统扩展")
                        .foregroundStyle(.white.opacity(0.46))
                }
                rowDivider
                settingRow(icon: "arrow.triangle.2.circlepath", color: .indigo, title: "同步") {
                    HStack(spacing: 8) {
                        if let last = syncModel.lastSync {
                            Text(last.formatted(date: .abbreviated, time: .shortened))
                                .foregroundStyle(.white.opacity(0.44))
                        }
                        Button {
                            Task {
                                if await syncModel.sync() { await onSync() }
                            }
                        } label: {
                            if syncModel.isSyncing {
                                ProgressView().controlSize(.small)
                            } else {
                                Text("立即同步")
                            }
                        }
                        .buttonStyle(.glass)
                        .disabled(syncModel.isSyncing)
                    }
                }
                if let error = syncModel.errorMessage {
                    rowDivider
                    Label(error, systemImage: "exclamationmark.triangle.fill")
                        .font(.system(size: 12))
                        .foregroundStyle(Color.orange)
                        .padding(15)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
    }

    private var appearanceCard: some View {
        settingsCard {
            VStack(spacing: 0) {
                VStack(alignment: .leading, spacing: 9) {
                    HStack {
                        settingIcon("drop.halffull", color: .white.opacity(0.75))
                        Text("液态玻璃着色")
                            .font(.system(size: 13.5))
                            .foregroundStyle(.white.opacity(0.90))
                        Spacer()
                        Text(glassTint, format: .percent.precision(.fractionLength(0)))
                            .font(.system(size: 12, design: .monospaced))
                            .foregroundStyle(.white.opacity(0.44))
                    }
                    Slider(value: $glassTint, in: 0...1)
                    HStack {
                        Text("清透")
                        Spacer()
                        Text("着色")
                    }
                    .font(.system(size: 10.5))
                    .foregroundStyle(.white.opacity(0.38))
                }
                .padding(15)
                rowDivider
                settingRow(icon: "circle.lefthalf.filled", color: .gray, title: "主题") {
                    Text("深色 · Mac 设计")
                        .foregroundStyle(.white.opacity(0.46))
                }
            }
        }
    }

    private var lockCard: some View {
        settingsCard {
            VStack(spacing: 0) {
                HStack {
                    Label("锁定保险库", systemImage: "lock.fill")
                        .font(.system(size: 13.5, weight: .semibold))
                    Spacer()
                    Button("立即锁定") {
                        Task {
                            await auth.lock()
                            await onAuthChange()
                        }
                    }
                    .buttonStyle(.glassProminent)
                }
                .padding(15)

                rowDivider

                HStack {
                    Label("退出当前账户", systemImage: "rectangle.portrait.and.arrow.right")
                        .font(.system(size: 13.5, weight: .semibold))
                    Spacer()
                    Button("退出", role: .destructive) {
                        Task {
                            await auth.logout()
                            await onAuthChange()
                        }
                    }
                }
                .padding(15)
            }
            .foregroundStyle(.white.opacity(0.92))
        }
    }

    private func sectionTitle(_ title: String) -> some View {
        Text(title)
            .font(.system(size: 11.5, weight: .semibold))
            .foregroundStyle(.white.opacity(0.42))
            .padding(.horizontal, 4)
            .padding(.bottom, -8)
    }

    private func settingsCard<Content: View>(@ViewBuilder content: () -> Content) -> some View {
        OpenVaultCard(cornerRadius: CornerRadius.macCard, padding: 0, content: content)
            .overlay {
                RoundedRectangle(cornerRadius: CornerRadius.macCard, style: .continuous)
                    .stroke(.white.opacity(0.07), lineWidth: 0.5)
            }
    }

    private func settingRow<Accessory: View>(icon: String, color: Color, title: String,
                                             @ViewBuilder accessory: () -> Accessory) -> some View {
        HStack(spacing: 11) {
            settingIcon(icon, color: color)
            Text(title)
                .font(.system(size: 13.5))
                .foregroundStyle(.white.opacity(0.90))
            Spacer()
            accessory()
                .font(.system(size: 12.5))
        }
        .padding(.horizontal, 15)
        .frame(minHeight: 50)
    }

    private func settingIcon(_ name: String, color: Color) -> some View {
        Image(systemName: name)
            .font(.system(size: 13, weight: .medium))
            .foregroundStyle(.white)
            .frame(width: 29, height: 29)
            .background(color, in: RoundedRectangle(cornerRadius: CornerRadius.settingIcon, style: .continuous))
    }

    private var rowDivider: some View {
        Divider().overlay(MacOpenVaultStyle.hairline).padding(.leading, 55)
    }

    private func label(for timeout: AutoLockTimeout) -> String {
        switch timeout {
        case .immediately: "立即"
        case .oneMinute: "1 分钟"
        case .fiveMinutes: "5 分钟"
        case .fifteenMinutes: "15 分钟"
        case .oneHour: "1 小时"
        case .never: "永不"
        }
    }
}
