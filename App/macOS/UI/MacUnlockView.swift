import SwiftUI
import UIShared
import DesignSystem

@available(macOS 27.0, *)
public struct MacUnlockView: View {
    @State private var model: UnlockModel
    private let onUnlocked: () -> Void

    public init(model: UnlockModel, onUnlocked: @escaping () -> Void) {
        _model = State(initialValue: model)
        self.onUnlocked = onUnlocked
    }

    private var isUnlocking: Bool { model.state == .unlocking }

    public var body: some View {
        @Bindable var model = model

        ZStack {
            OpenVaultLockBackground()
            VStack(spacing: 22) {
                VStack(spacing: 10) {
                    OpenVaultMark(size: 76)
                    Text("OpenVault")
                        .font(.system(size: 25, weight: .bold))
                        .foregroundStyle(.white)
                    Text("保险库已锁定")
                        .font(.system(size: 13.5))
                        .foregroundStyle(.white.opacity(0.52))
                }

                Button {
                    Task { await model.unlockWithBiometrics(reason: "使用触控 ID 解锁 OpenVault") }
                } label: {
                    ZStack {
                        Circle().fill(.white.opacity(0.055))
                        if isUnlocking {
                            ProgressView().controlSize(.small)
                        } else if model.state == .unlocked {
                            Image(systemName: "checkmark")
                                .font(.system(size: 27, weight: .semibold))
                                .foregroundStyle(Color.green)
                        } else {
                            Image(systemName: "touchid")
                                .font(.system(size: 31, weight: .regular))
                                .foregroundStyle(.white.opacity(0.92))
                        }
                    }
                    .frame(width: 82, height: 82)
                }
                .buttonStyle(.plain)
                .glassStyle(in: Circle())
                .disabled(isUnlocking)
                .accessibilityLabel("使用触控 ID 解锁")

                OpenVaultCard(cornerRadius: 18, padding: 16) {
                    HStack(spacing: 10) {
                        Image(systemName: "key")
                            .foregroundStyle(.white.opacity(0.42))
                        SecureField("主密码", text: $model.password)
                            .textFieldStyle(.plain)
                            .textContentType(.password)
                            .onSubmit(unlock)
                        Button(action: unlock) {
                            Image(systemName: "arrow.right")
                                .frame(width: 26, height: 26)
                        }
                        .buttonStyle(.glassProminent)
                        .disabled(model.password.isEmpty || isUnlocking)
                    }
                }
                .frame(width: 360)
                .overlay {
                    RoundedRectangle(cornerRadius: 18, style: .continuous)
                        .stroke(.white.opacity(0.10), lineWidth: 0.5)
                }

                if let message = model.errorMessage {
                    Label(message, systemImage: "exclamationmark.triangle.fill")
                        .font(.system(size: 12.5))
                        .foregroundStyle(Color.orange)
                        .frame(width: 360, alignment: .leading)
                } else {
                    Text(isUnlocking ? "正在验证…" : "触控 ID 或主密码均在本机验证")
                        .font(.system(size: 11.5))
                        .foregroundStyle(.white.opacity(0.34))
                }
            }
            .padding(40)
        }
        .onChange(of: model.state) { _, newValue in
            if newValue == .unlocked { onUnlocked() }
        }
    }

    private func unlock() {
        guard !model.password.isEmpty, !isUnlocking else { return }
        Task { await model.unlockWithPassword() }
    }
}
