import SwiftUI
import LocalAuthentication
import UIShared
import DesignSystem

@available(iOS 27.0, *)
public struct UnlockView: View {
    @State private var model: UnlockModel
    private let biometricsEnabled: Bool
    private let onUnlocked: () -> Void

    @State private var showingPassword = false
    @State private var biometry: LABiometryType = .none
    @FocusState private var passwordFocused: Bool

    public init(model: UnlockModel, biometricsEnabled: Bool = true,
                onUnlocked: @escaping () -> Void) {
        _model = State(initialValue: model)
        self.biometricsEnabled = biometricsEnabled
        self.onUnlocked = onUnlocked
    }

    private var isUnlocking: Bool { model.state == .unlocking }

    public var body: some View {
        ScrollView {
            VStack(spacing: Spacing.xxxl) {
                VStack(spacing: Spacing.sm) {
                    OpenVaultMark(size: 86)
                        .padding(.bottom, Spacing.sm)
                    Text("OpenVault")
                        .font(.title.bold())
                        .accessibilityAddTraits(.isHeader)
                    Text("保险库已锁定")
                        .font(.body)
                        .foregroundStyle(.secondary)
                }

                VStack(spacing: Spacing.md) {
                    if let biometricAction {
                        Button {
                            Task { await model.unlockWithBiometrics(reason: "解锁 OpenVault") }
                        } label: {
                            Label {
                                Text(isUnlocking ? "正在验证…" : biometricAction.title)
                            } icon: {
                                if isUnlocking {
                                    ProgressView().accessibilityHidden(true)
                                } else {
                                    Image(systemName: biometricAction.symbol)
                                }
                            }
                            .frame(maxWidth: .infinity)
                        }
                        .vaultProminentButtonStyle(glass: true)
                        passwordButton.buttonStyle(.bordered)
                    } else {
                        passwordButton.vaultProminentButtonStyle(glass: true)
                    }

                    if let message = model.errorMessage {
                        errorLabel(message)
                    }

                    Text("忘记主密码？请联系保险库管理员")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                .controlSize(.large)
                .disabled(isUnlocking)
            }
            .multilineTextAlignment(.center)
            .padding(Spacing.xl)
            .frame(maxWidth: 420)
            .frame(maxWidth: .infinity)
        }
        .defaultScrollAnchor(.center, for: .alignment)
        .scrollBounceBehavior(.basedOnSize)
        .background(Palette.groupedBackground)
        .onAppear(perform: resolveBiometry)
        .onChange(of: model.state) { _, newValue in
            if newValue == .unlocked {
                showingPassword = false
                onUnlocked()
            }
        }
        .sheet(isPresented: $showingPassword) {
            passwordSheet
        }
    }

    private var biometricAction: (title: String, symbol: String)? {
        switch biometry {
        case .faceID: ("使用面容 ID 解锁", "faceid")
        case .touchID: ("使用触控 ID 解锁", "touchid")
        default: nil
        }
    }

    private var passwordButton: some View {
        Button { showingPassword = true } label: {
            Label("使用主密码解锁", systemImage: "key")
                .frame(maxWidth: .infinity)
        }
    }

    private var passwordSheet: some View {
        NavigationStack {
            Form {
                Section("主密码") {
                    SecureField("输入主密码", text: $model.password)
                        .textContentType(.password)
                        .focused($passwordFocused)
                        .submitLabel(.go)
                        .onSubmit(unlockWithPassword)
                        .privacySensitive()
                        .listRowBackground(Palette.contentBackground)
                }
                if let message = model.errorMessage {
                    errorLabel(message)
                }
            }
            .formStyle(.grouped)
            .scrollContentBackground(.hidden)
            .navigationTitle("使用主密码")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("取消") { showingPassword = false }
                }
                ToolbarItem(placement: .confirmationAction) {
                    if isUnlocking {
                        ProgressView().accessibilityLabel("正在验证")
                    } else {
                        Button("解锁", action: unlockWithPassword)
                            .disabled(model.password.isEmpty)
                    }
                }
            }
            .onAppear { passwordFocused = true }
        }
    }

    private func errorLabel(_ message: String) -> some View {
        Label(message, systemImage: "exclamationmark.triangle.fill")
            .font(.subheadline)
            .foregroundStyle(Palette.danger)
    }

    private func unlockWithPassword() {
        guard !model.password.isEmpty, !isUnlocking else { return }
        passwordFocused = false
        Task { await model.unlockWithPassword() }
    }

    private func resolveBiometry() {
        guard biometricsEnabled else { return }
        let context = LAContext()
        biometry = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
            ? context.biometryType : .none
    }
}
