import SwiftUI
import UIShared
import DesignSystem
import AppShared

struct MacSettingsView: View {
    private let auth: AuthService
    @State private var syncModel: SyncStatusModel
    @State private var settings: SettingsModel
    @State private var touchIDAvailable = false
    private let onSync: () async -> Void
    private let onAuthChange: () async -> Void

    @AppStorage(OpenVaultPreferenceKey.theme) private var theme = OpenVaultTheme.system
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
        Form {
            Section("账户") {
                HStack(spacing: 12) {
                    OpenVaultMark(size: 42)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("OpenVault").font(.headline)
                        Text(settings.serverURL.nilIfBlank ?? "尚未设置服务器")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                }
            }

            Section("安全") {
                Picker("自动锁定", selection: $settings.autoLockTimeout) {
                    ForEach(settings.availableTimeouts, id: \.self) { timeout in
                        Text(label(for: timeout)).tag(timeout)
                    }
                }
                #if !OPENVAULT_LOCAL
                Toggle(isOn: $settings.biometricUnlockEnabled) {
                    VStack(alignment: .leading) {
                        Text("使用触控 ID")
                        if !touchIDAvailable {
                            Text("此 Mac 当前无法使用触控 ID。")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                .disabled(!touchIDAvailable && !settings.biometricUnlockEnabled)
                #endif
                Picker("清除剪贴板", selection: $clipboardTimeout) {
                    Text("永不").tag(0.0)
                    Text("30 秒").tag(30.0)
                    Text("1 分钟").tag(60.0)
                    Text("2 分钟").tag(120.0)
                    Text("5 分钟").tag(300.0)
                }
            }

            Section {
                #if !OPENVAULT_LOCAL
                LabeledContent("密码自动填充", value: "系统扩展")
                #endif
                HStack {
                    Text("同步")
                    Spacer()
                    if let last = syncModel.lastSync {
                        Text(last.formatted(date: .abbreviated, time: .shortened))
                            .foregroundStyle(.secondary)
                    }
                    if syncModel.isSyncing {
                        ProgressView("正在同步").controlSize(.small)
                    } else {
                        Button("立即同步") {
                            Task { if await syncModel.sync() { await onSync() } }
                        }
                    }
                }
                .accessibilityElement(children: .contain)
                if let error = syncModel.errorMessage {
                    Label(error, systemImage: "exclamationmark.triangle")
                }
            } header: {
                #if OPENVAULT_LOCAL
                Text("同步")
                #else
                Text("自动填充与同步")
                #endif
            }

            Section("外观") {
                Picker("主题", selection: $theme) {
                    Text("跟随系统").tag(OpenVaultTheme.system)
                    Text("浅色").tag(OpenVaultTheme.light)
                    Text("深色").tag(OpenVaultTheme.dark)
                }
            }

            Section {
                Button("锁定保险库") {
                    Task {
                        await auth.lock()
                        await onAuthChange()
                    }
                }
                Button("退出当前账户", role: .destructive) {
                    Task {
                        await auth.logout()
                        await onAuthChange()
                    }
                }
            }
        }
        .formStyle(.grouped)
        #if !OPENVAULT_LOCAL
        .modifier(MacTouchIDAvailability(isAvailable: $touchIDAvailable))
        #endif
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
