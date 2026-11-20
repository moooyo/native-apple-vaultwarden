import SwiftUI
import LocalAuthentication
import UIShared
import DesignSystem

public struct MacUnlockView: View {
    @State private var model: UnlockModel
    @State private var touchIDAvailable = false
    private let biometricsEnabled: Bool
    private let onUnlocked: () -> Void

    public init(model: UnlockModel, biometricsEnabled: Bool = false,
                onUnlocked: @escaping () -> Void) {
        _model = State(initialValue: model)
        self.biometricsEnabled = biometricsEnabled
        self.onUnlocked = onUnlocked
    }

    private var isUnlocking: Bool { model.state == .unlocking }

    public var body: some View {
        @Bindable var model = model

        ZStack {
            OpenVaultLockBackground()
            VStack(spacing: Spacing.xl) {
                VStack(spacing: Spacing.sm) {
                    OpenVaultMark(size: 76)
                    Text("OpenVault")
                        .font(.title.bold())
                        .accessibilityAddTraits(.isHeader)
                    Text("保险库已锁定")
                        .foregroundStyle(.secondary)
                }

                if biometricsEnabled && touchIDAvailable {
                    Button("使用触控 ID 解锁", systemImage: "touchid") {
                        Task { await model.unlockWithBiometrics(reason: "使用触控 ID 解锁 OpenVault") }
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    .disabled(isUnlocking)
                }

                HStack {
                    SecureField("主密码", text: $model.password)
                        .textFieldStyle(.roundedBorder)
                        .textContentType(.password)
                        .onSubmit(unlock)
                    Button("解锁", action: unlock)
                        .accessibilityLabel("使用主密码解锁")
                        .disabled(model.password.isEmpty || isUnlocking)
                }
                .controlSize(.large)

                if isUnlocking {
                    ProgressView("正在验证…").controlSize(.small)
                } else if let message = model.errorMessage {
                    Label(message, systemImage: "exclamationmark.triangle.fill")
                        .font(.callout)
                        .frame(maxWidth: .infinity, alignment: .leading)
                } else if model.state == .unlocked {
                    Label("已解锁", systemImage: "checkmark.circle")
                        .foregroundStyle(.secondary)
                }
            }
            .frame(maxWidth: 340)
            .padding(Spacing.xxl)
        }
        .modifier(MacTouchIDAvailability(isAvailable: $touchIDAvailable, enabled: biometricsEnabled))
        .onChange(of: model.state) { _, newValue in
            if newValue == .unlocked { onUnlocked() }
        }
    }

    private func unlock() {
        guard !model.password.isEmpty, !isUnlocking else { return }
        Task { await model.unlockWithPassword() }
    }
}

/// Refresh when a window or menu returns, not on each vault lock-state poll.
struct MacTouchIDAvailability: ViewModifier {
    @Binding var isAvailable: Bool
    var enabled = true
    @Environment(\.appearsActive) private var appearsActive

    func body(content: Content) -> some View {
        content
            .onAppear(perform: refresh)
            .onChange(of: enabled) { _, _ in refresh() }
            .onChange(of: appearsActive) { _, active in if active { refresh() } }
    }

    private func refresh() {
        guard enabled else { isAvailable = false; return }
        let context = LAContext()
        isAvailable = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
            && context.biometryType == .touchID
    }
}
