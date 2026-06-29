// Xcode-only target (UI-iOS / UI-mac). Not part of the SPM build.
//
// UnlockView — unlock an already-signed-in account with the master password or
// biometrics. The master-password field is a system `SecureField` (masked), so the
// secret is never rendered on clear glass; the only glass here is the chrome.

import SwiftUI
import UIShared
import DesignSystem

@available(iOS 26.0, *)
public struct UnlockView: View {
    @State private var model: UnlockModel
    /// Called once the model reaches `.unlocked`.
    private let onUnlocked: () -> Void
    @FocusState private var passwordFocused: Bool

    public init(model: UnlockModel, onUnlocked: @escaping () -> Void) {
        _model = State(initialValue: model)
        self.onUnlocked = onUnlocked
    }

    private var isUnlocking: Bool { model.state == .unlocking }

    public var body: some View {
        VStack(spacing: Spacing.xl) {
            Spacer()

            Image(systemName: "lock.fill")
                .font(.system(size: 56, weight: .semibold))
                .foregroundStyle(Palette.accent)
                .accessibilityHidden(true)

            VStack(spacing: Spacing.xs) {
                Text("Vault Locked")
                    .font(Typography.screenTitle)
                Text("Enter your master password to unlock.")
                    .font(Typography.rowSubtitle)
                    .foregroundStyle(Palette.secondaryText)
                    .multilineTextAlignment(.center)
            }

            VStack(spacing: Spacing.md) {
                SecureField("Master password", text: $model.password)
                    .textContentType(.password)
                    .focused($passwordFocused)
                    .submitLabel(.go)
                    .onSubmit { unlock() }
                    .padding(Spacing.md)
                    .background {
                        // Sensitive entry sits on the opaque content layer, never clear glass.
                        RoundedRectangle(cornerRadius: CornerRadius.md, style: .continuous)
                            .fill(Palette.contentBackground)
                    }

                if let message = model.errorMessage {
                    Label(message, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(Palette.danger)
                        .font(Typography.rowSubtitle)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }

                Button(action: unlock) {
                    HStack {
                        Spacer()
                        if isUnlocking {
                            ProgressView()
                        } else {
                            Text("Unlock").fontWeight(.semibold)
                        }
                        Spacer()
                    }
                    .padding(.vertical, Spacing.xs)
                }
                .buttonStyle(.borderedProminent)
                .disabled(model.password.isEmpty || isUnlocking)

                Button {
                    Task { await model.unlockWithBiometrics() }
                } label: {
                    Label("Unlock with Face ID", systemImage: "faceid")
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, Spacing.xs)
                }
                .buttonStyle(.bordered)
                .disabled(isUnlocking)
            }
            .padding(.horizontal, Spacing.xl)

            Spacer()
            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Palette.groupedBackground)
        .onChange(of: model.state) { _, newValue in
            if newValue == .unlocked { onUnlocked() }
        }
        .onAppear { passwordFocused = true }
    }

    private func unlock() {
        passwordFocused = false
        Task { await model.unlockWithPassword() }
    }
}
