// Xcode-only target (UI-iOS / UI-mac). Not part of the SPM build.
//
// SettingsView — server URL, auto-lock timeout, biometric toggle, manual sync, lock-now,
// and logout. Edits the in-memory `SettingsModel`; persistence to App Group UserDefaults
// is the App target's job (the model is purely the editable view).
//
// Lock-now / logout call `AuthService` then ask the root to re-route via `onAuthChange`.

import SwiftUI
import UIShared
import DesignSystem
import AppShared

@available(iOS 26.0, *)
public struct SettingsView: View {
    private let auth: AuthService
    @State private var syncModel: SyncStatusModel
    @State private var settings: SettingsModel
    private let onAuthChange: () async -> Void

    @State private var showingLogoutConfirm = false

    public init(auth: AuthService, syncModel: SyncStatusModel, settings: SettingsModel,
                onAuthChange: @escaping () async -> Void) {
        self.auth = auth
        _syncModel = State(initialValue: syncModel)
        _settings = State(initialValue: settings)
        self.onAuthChange = onAuthChange
    }

    public var body: some View {
        Form {
            Section("Server") {
                LabeledContent("URL") {
                    Text(settings.serverURL.isEmpty ? "Not set" : settings.serverURL)
                        .foregroundStyle(Palette.secondaryText)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                if !settings.isServerURLValid && !settings.serverURL.isEmpty {
                    Label("This URL doesn't look valid.", systemImage: "exclamationmark.triangle")
                        .font(Typography.caption)
                        .foregroundStyle(Palette.warning)
                }
            }

            Section("Security") {
                Picker("Auto-lock", selection: $settings.autoLockTimeout) {
                    ForEach(settings.availableTimeouts, id: \.self) { timeout in
                        Text(label(for: timeout)).tag(timeout)
                    }
                }
                Toggle("Unlock with Face ID / Touch ID", isOn: $settings.biometricUnlockEnabled)
            }

            Section("Sync") {
                Button {
                    Task { await syncModel.sync() }
                } label: {
                    HStack {
                        Label("Sync now", systemImage: "arrow.triangle.2.circlepath")
                        Spacer()
                        if syncModel.isSyncing { ProgressView().controlSize(.small) }
                    }
                }
                .disabled(syncModel.isSyncing)

                if let last = syncModel.lastSync {
                    LabeledContent("Last sync") {
                        Text(last.formatted(date: .abbreviated, time: .shortened))
                            .foregroundStyle(Palette.secondaryText)
                    }
                }
                if let outcome = syncModel.lastOutcome, outcome.dropped > 0 {
                    Label("\(outcome.dropped) item(s) could not be decoded.",
                          systemImage: "exclamationmark.circle")
                        .font(Typography.caption)
                        .foregroundStyle(Palette.warning)
                }
                if let error = syncModel.errorMessage {
                    Label(error, systemImage: "exclamationmark.triangle.fill")
                        .font(Typography.caption)
                        .foregroundStyle(Palette.danger)
                }
            }

            Section {
                Button(role: .destructive) {
                    Task { await auth.lock(); await onAuthChange() }
                } label: {
                    Label("Lock now", systemImage: "lock")
                }
                Button(role: .destructive) {
                    showingLogoutConfirm = true
                } label: {
                    Label("Log out", systemImage: "rectangle.portrait.and.arrow.right")
                }
            }
        }
        .navigationTitle("Settings")
        .confirmationDialog("Log out of this account?", isPresented: $showingLogoutConfirm,
                            titleVisibility: .visible) {
            Button("Log Out", role: .destructive) {
                Task { await auth.logout(); await onAuthChange() }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Your offline vault stays encrypted on this device until you remove the account.")
        }
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
