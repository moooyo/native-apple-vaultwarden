import SwiftUI
import UIShared
import DesignSystem
import Networking

@available(macOS 27.0, *)
public struct MacLoginView: View {
    @State private var model: LoginModel
    @State private var showTwoFactor = false
    private let onLoggedIn: (String) -> Void

    public init(model: LoginModel, onLoggedIn: @escaping (String) -> Void) {
        _model = State(initialValue: model)
        self.onLoggedIn = onLoggedIn
    }

    private var isSubmitting: Bool { model.state == .submitting }
    private var canSubmit: Bool {
        !model.serverURL.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && !model.email.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && !model.password.isEmpty
            && !isSubmitting
    }

    public var body: some View {
        @Bindable var model = model

        ZStack {
            OpenVaultLockBackground()
            ScrollView {
                VStack(spacing: 24) {
                    VStack(spacing: 10) {
                        OpenVaultMark(size: 76)
                        Text("OpenVault")
                            .font(.system(size: 25, weight: .bold))
                            .foregroundStyle(.white)
                        Text("登录你的加密保险库")
                            .font(.system(size: 13.5))
                            .foregroundStyle(.white.opacity(0.52))
                    }

                    OpenVaultCard(cornerRadius: 20, padding: 22) {
                        VStack(spacing: 14) {
                            loginField("服务器 URL", text: $model.serverURL, prompt: "https://vault.example.com", icon: "server.rack")
                            Divider().overlay(.white.opacity(0.08))
                            loginField("邮箱", text: $model.email, prompt: "name@example.com", icon: "envelope")
                            Divider().overlay(.white.opacity(0.08))
                            HStack(spacing: 10) {
                                Image(systemName: "key")
                                    .foregroundStyle(.white.opacity(0.44))
                                    .frame(width: 18)
                                SecureField("主密码", text: $model.password)
                                    .textFieldStyle(.plain)
                                    .textContentType(.password)
                                    .onSubmit(submit)
                            }
                            .frame(minHeight: 30)
                        }
                    }
                    .frame(maxWidth: 430)
                    .overlay {
                        RoundedRectangle(cornerRadius: 20, style: .continuous)
                            .stroke(.white.opacity(0.10), lineWidth: 0.5)
                    }

                    if let message = model.errorMessage {
                        Label(message, systemImage: "exclamationmark.triangle.fill")
                            .font(.system(size: 12.5))
                            .foregroundStyle(Color.orange)
                            .frame(maxWidth: 430, alignment: .leading)
                    }

                    Button(action: submit) {
                        Group {
                            if isSubmitting {
                                ProgressView().controlSize(.small)
                            } else {
                                Label("登录", systemImage: "arrow.right")
                            }
                        }
                        .font(.system(size: 14, weight: .semibold))
                        .frame(maxWidth: .infinity, minHeight: 38)
                    }
                    .buttonStyle(.glassProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(!canSubmit)
                    .frame(maxWidth: 430)

                    Text("凭据只用于在本机解密保险库")
                        .font(.system(size: 11.5))
                        .foregroundStyle(.white.opacity(0.34))
                }
                .padding(.vertical, 56)
                .padding(.horizontal, 32)
                .frame(maxWidth: .infinity)
            }
        }
        .onChange(of: model.state) { _, newValue in
            switch newValue {
            case .needsTwoFactor:
                showTwoFactor = true
            case .success:
                showTwoFactor = false
                onLoggedIn(model.serverURL)
            default:
                break
            }
        }
        .sheet(isPresented: $showTwoFactor) {
            MacTwoFactorView(
                providers: model.twoFactorProviders,
                isSubmitting: isSubmitting,
                errorMessage: model.errorMessage,
                onResendEmail: { Task { await model.resendTwoFactorEmail() } }
            ) { code, provider, remember in
                Task { await model.submitTwoFactor(code: code, provider: provider, remember: remember) }
            }
        }
    }

    private func loginField(_ title: String, text: Binding<String>, prompt: String, icon: String) -> some View {
        HStack(spacing: 10) {
            Image(systemName: icon)
                .foregroundStyle(.white.opacity(0.44))
                .frame(width: 18)
            TextField(title, text: text, prompt: Text(prompt).foregroundStyle(.white.opacity(0.28)))
                .textFieldStyle(.plain)
        }
        .frame(minHeight: 30)
    }

    private func submit() {
        guard canSubmit else { return }
        Task { await model.submit() }
    }
}

@available(macOS 27.0, *)
struct MacTwoFactorView: View {
    let providers: [TwoFactorProvider]
    let isSubmitting: Bool
    let errorMessage: String?
    let onResendEmail: () -> Void
    let onSubmit: (String, TwoFactorProvider, Bool) -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var code = ""
    @State private var rememberDevice = false
    @State private var selectedProvider: TwoFactorProvider

    init(providers: [TwoFactorProvider], isSubmitting: Bool, errorMessage: String?,
         onResendEmail: @escaping () -> Void,
         onSubmit: @escaping (String, TwoFactorProvider, Bool) -> Void) {
        self.providers = providers
        self.isSubmitting = isSubmitting
        self.errorMessage = errorMessage
        self.onResendEmail = onResendEmail
        self.onSubmit = onSubmit
        _selectedProvider = State(initialValue: providers.first {
            $0 == .authenticator || $0 == .email
        } ?? providers.first ?? .authenticator)
    }

    private var supportedProviders: [TwoFactorProvider] {
        providers.filter { $0 == .authenticator || $0 == .email }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(spacing: 12) {
                OpenVaultMark(size: 42)
                VStack(alignment: .leading, spacing: 2) {
                    Text("两步登录")
                        .font(.system(size: 18, weight: .bold))
                    Text("输入验证器或邮箱中的验证码")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                }
            }

            if supportedProviders.count > 1 {
                Picker("方式", selection: $selectedProvider) {
                    ForEach(supportedProviders, id: \.self) { provider in
                        Text(provider == .email ? "邮箱" : "验证器").tag(provider)
                    }
                }
                .pickerStyle(.segmented)
            }

            TextField("验证码", text: $code)
                .font(.system(size: 18, weight: .medium, design: .monospaced))
                .textFieldStyle(.roundedBorder)
                .onSubmit(submit)

            if selectedProvider == .email {
                Button("重新发送邮箱验证码", action: onResendEmail)
                    .disabled(isSubmitting)
            }

            Toggle("记住此设备", isOn: $rememberDevice)

            if supportedProviders.isEmpty {
                Label("服务器要求的验证方式尚不受支持。", systemImage: "exclamationmark.triangle")
                    .foregroundStyle(Color.orange)
            } else if let errorMessage {
                Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(Color.orange)
            }

            HStack {
                Button("取消") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button("验证", action: submit)
                    .buttonStyle(.glassProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(code.trimmingCharacters(in: .whitespaces).isEmpty || isSubmitting || supportedProviders.isEmpty)
            }
        }
        .padding(24)
        .frame(width: 390)
    }

    private func submit() {
        guard supportedProviders.contains(selectedProvider) else { return }
        onSubmit(code, selectedProvider, rememberDevice)
    }
}

@available(macOS 27.0, *)
struct OpenVaultLockBackground: View {
    var body: some View {
        ZStack {
            Color(red: 11 / 255, green: 13 / 255, blue: 20 / 255)
            RadialGradient(
                colors: [
                    Color(red: 35 / 255, green: 43 / 255, blue: 66 / 255),
                    Color(red: 21 / 255, green: 25 / 255, blue: 38 / 255).opacity(0.92),
                    .clear
                ],
                center: UnitPoint(x: 0.5, y: 0.0),
                startRadius: 0,
                endRadius: 620
            )
        }
        .ignoresSafeArea()
    }
}
