// Xcode-only target (UI-iOS / UI-mac). Not part of the SPM build.
//
// MacSettingsView — server, auto-lock timeout, biometric toggle, manual sync, lock-now,
// and logout for macOS. Presented as a sheet from `MacMainView` (the App target may also
// host this in a `Settings` scene). Edits the in-memory `SettingsModel`.

import SwiftUI
import UIShared
import DesignSystem
import AppShared

@available(macOS 26.0, *)
struct MacSettingsView: View {
    private let auth: AuthService
    @State private var syncModel: SyncStatusModel
    @State private var settings: SettingsModel
    private let onAuthChange: () async -> Void

    @Environment(\.dismiss) private var dismiss

    init(auth: AuthService, syncModel: SyncStatusModel, settings: SettingsModel,
         onAuthChange: @escaping () async -> Void) {
        self.auth = auth
        _syncModel = State(initialValue: syncModel)
        _settings = State(initialValue: settings)
        self.onAuthChange = onAuthChange
    }

    var body: some View {
        VStack(spacing: 0) {
            Form {
                Section("Server") {
                    LabeledContent("URL") {
                        Text(settings.serverURL.isEmpty ? "Not set" : settings.serverURL)
                            .foregroundStyle(Palette.secondaryText)
                            .lineLimit(1).truncationMode(.middle)
                    }
                }

                Section("Security") {
                    Picker("Auto-lock", selection: $settings.autoLockTimeout) {
                        ForEach(settings.availableTimeouts, id: \.self) { timeout in
                            Text(label(for: timeout)).tag(timeout)
                        }
                    }
                    Toggle("Unlock with Touch ID", isOn: $settings.biometricUnlockEnabled)
                }

                Section("Sync") {
                    Button {
                        Task { await syncModel.sync() }
                    } label: {
                        Label("Sync now", systemImage: "arrow.triangle.2.circlepath")
                    }
                    .disabled(syncModel.isSyncing)

                    if let last = syncModel.lastSync {
                        LabeledContent("Last sync") {
                            Text(last.formatted(date: .abbreviated, time: .shortened))
                                .foregroundStyle(Palette.secondaryText)
                        }
                    }
                }

                Section {
                    Button {
                        Task { await auth.lock(); await onAuthChange(); dismiss() }
                    } label: {
                        Label("Lock now", systemImage: "lock")
                    }
                    Button(role: .destructive) {
                        Task { await auth.logout(); await onAuthChange(); dismiss() }
                    } label: {
                        Label("Log out", systemImage: "rectangle.portrait.and.arrow.right")
                    }
                }
            }
            .formStyle(.grouped)

            Divider()
            HStack {
                Spacer()
                Button("Done") { dismiss() }
                    .keyboardShortcut(.defaultAction)
            }
            .padding(Spacing.lg)
        }
        .frame(width: 460, height: 460)
    }

    private func label(for timeout: AutoLockTimeout) -> String {
        switch timeout {
        case .immediately: return "Immediately"
        case .oneMinute: return "1 minute"
        case .fiveMinutes: return "5 minutes"
        case .fifteenMinutes: return "15 minutes"
        case .oneHour: return "1 hour"
        case .never: return "Never"
        }
    }
}
