import SwiftUI
import LocalAuthentication
import UIShared
import DesignSystem

@available(iOS 27.0, *)
public struct UnlockView: View {
    @State private var model: UnlockModel
    @State private var passwordMode = false
    @State private var confirmingLogout = false
    @State private var biometry: LABiometryType = .none
    @FocusState private var passwordFocused: Bool
    @Environment(\.horizontalSizeClass) private var widthClass
    @Environment(\.scenePhase) private var scenePhase
    private let biometricsEnabled: Bool
    private let onLoggedOut: () -> Void
    private let onUnlocked: () -> Void

    public init(model: UnlockModel, biometricsEnabled: Bool = true,
                onLoggedOut: @escaping () -> Void = {}, onUnlocked: @escaping () -> Void) {
        _model = State(initialValue: model)
        self.biometricsEnabled = biometricsEnabled
        self.onLoggedOut = onLoggedOut
        self.onUnlocked = onUnlocked
    }

    public var body: some View {
        NavigationStack {
            GeometryReader { geometry in
                ScrollView {
                    VStack(spacing: 0) {
                        Spacer(minLength: 16)
                        VStack(spacing: 6) {
                            OpenVaultMark(size: 96).padding(.bottom, 18)
                            Text("保险库已锁定").font(.title2.bold()).accessibilityAddTraits(.isHeader)
                            if let email = model.email {
                                Text(email).foregroundStyle(.secondary).privacySensitive()
                            }
                        }
                        .multilineTextAlignment(.center)
                        if widthClass == .regular { Color.clear.frame(height: 48) }
                        else { Spacer(minLength: 32) }
                        actions.frame(maxWidth: 400)
                        if widthClass == .regular { Spacer(minLength: 16) }
                    }
                    .padding(.horizontal, Spacing.lg)
                    .padding(.bottom, Spacing.lg)
                    .frame(maxWidth: .infinity, minHeight: geometry.size.height)
                }
                .scrollBounceBehavior(.basedOnSize)
                .scrollDismissesKeyboard(.interactively)
            }
            .background(Palette.groupedBackground)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Menu("更多", systemImage: "ellipsis") {
                        Button("退出登录…", systemImage: "rectangle.portrait.and.arrow.right", role: .destructive) {
                            confirmingLogout = true
                        }
                    }
                    .disabled(model.state == .unlocking)
                }
            }
            .alert("退出登录？", isPresented: $confirmingLogout) {
                Button("取消", role: .cancel) {}
                Button("退出登录", role: .destructive) {
                    Task { if await model.logout() { onLoggedOut() } }
                }
            } message: { Text("本机将移除登录凭据和生成历史。再次访问保险库需要重新登录。") }
        }
        .task { await model.loadAccount() }
        .onChange(of: scenePhase, initial: true) { _, phase in
            guard phase == .active else { return }
            let context = LAContext()
            biometry = biometricsEnabled && context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
                ? context.biometryType : .none
        }
        .onChange(of: model.state) { _, state in if state == .unlocked { onUnlocked() } }
        .onChange(of: passwordMode) { _, enabled in passwordFocused = enabled }
    }

    private var biometric: (title: String, icon: String)? {
        switch biometry {
        case .faceID: ("面容 ID", "faceid")
        case .touchID: ("触控 ID", "touchid")
        default: nil
        }
    }

    private var actions: some View {
        VStack(spacing: Spacing.md) {
            if let message = model.errorMessage { LoginMessage(message: message) }
            if let biometric, !passwordMode {
                Button {
                    Task { await model.unlockWithBiometrics(reason: "解锁 OpenVault") }
                } label: {
                    Label(model.state == .unlocking ? "正在验证…" : "使用\(biometric.title)解锁", systemImage: biometric.icon)
                        .frame(maxWidth: .infinity, minHeight: 44)
                }
                .vaultProminentButtonStyle()
                Button { passwordMode = true } label: { Text("使用主密码").frame(maxWidth: .infinity, minHeight: 44) }
                    .buttonStyle(.bordered)
            } else {
                OpenVaultCard(padding: 0) {
                    SecureField("主密码", text: $model.password)
                        .textContentType(.password)
                        .focused($passwordFocused)
                        .privacySensitive()
                        .submitLabel(.go)
                        .onSubmit(unlock)
                        .accessibilityIdentifier("unlock.password")
                        .padding(.horizontal, Spacing.lg)
                        .frame(minHeight: 56)
                }
                Button(action: unlock) {
                    Text(model.state == .unlocking ? "正在验证…" : "解锁").frame(maxWidth: .infinity, minHeight: 44)
                }
                .vaultProminentButtonStyle()
                .disabled(model.password.isEmpty)
                .accessibilityIdentifier("unlock.submit")
                if let biometric {
                    Button { model.password = ""; passwordMode = false } label: {
                        Text("使用\(biometric.title)").frame(maxWidth: .infinity, minHeight: 44)
                    }
                    .buttonStyle(.bordered)
                }
            }
        }
        .buttonBorderShape(.capsule)
        .disabled(model.state == .unlocking)
    }

    private func unlock() {
        guard !model.password.isEmpty, model.state != .unlocking else { return }
        passwordFocused = false
        Task { await model.unlockWithPassword() }
    }
}
