// Xcode-only target (UI-iOS / UI-mac). Not part of the SPM build.
//
// MacUnlockView — unlock an already-signed-in account on macOS with the master password
// or Touch ID. The password is entered via a `SecureField` (masked); never on clear glass.

import SwiftUI
import UIShared
import DesignSystem

@available(macOS 26.0, *)
public struct MacUnlockView: View {
    @State private var model: UnlockModel
    private let onUnlocked: () -> Void

    public init(model: UnlockModel, onUnlocked: @escaping () -> Void) {
        _model = State(initialValue: model)
        self.onUnlocked = onUnlocked
    }

    private var isUnlocking: Bool { model.state == .unlocking }

    public var body: some View {
        VStack(spacing: Spacing.xl) {
            Image(systemName: "lock.fill")
                .font(.system(size: 48, weight: .semibold))
                .foregroundStyle(Palette.accent)

            Text("Vault Locked").font(Typography.sectionTitle)

            SecureField("Master password", text: $model.password)
                .textContentType(.password)
                .frame(maxWidth: 300)
                .onSubmit { unlock() }

            if let message = model.errorMessage {
                Label(message, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(Palette.danger)
                    .font(Typography.rowSubtitle)
            }

            HStack(spacing: Spacing.md) {
                Button {
                    Task { await model.unlockWithBiometrics() }
                } label: {
                    Label("Touch ID", systemImage: "touchid")
                }
                .buttonStyle(.bordered)
                .disabled(isUnlocking)

                Button(action: unlock) {
                    if isUnlocking {
                        ProgressView().controlSize(.small)
                    } else {
                        Text("Unlock")
                    }
                }
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.defaultAction)
                .disabled(model.password.isEmpty || isUnlocking)
            }
        }
        .padding(Spacing.xxl)
        .onChange(of: model.state) { _, newValue in
            if newValue == .unlocked { onUnlocked() }
        }
    }

    private func unlock() {
        Task { await model.unlockWithPassword() }
    }
}
