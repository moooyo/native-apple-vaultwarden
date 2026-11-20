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
                VStack(spacing: Spacing.xl) {
                    VStack(spacing: Spacing.sm) {
                        OpenVaultMark(size: 76)
                        Text("OpenVault")
                            .font(.title.bold())
                            .accessibilityAddTraits(.isHeader)
                        Text("登录你的加密保险库")
                            .foregroundStyle(.secondary)
                    }

                    Form {
                        TextField("服务器 URL", text: $model.serverURL, prompt: Text("https://vault.example.com"))
                        TextField("邮箱", text: $model.email, prompt: Text("name@example.com"))
                            .textContentType(.username)
                        SecureField("主密码", text: $model.password)
                            .textContentType(.password)
                            .onSubmit(submit)
                    }
                    .formStyle(.columns)
                    .textFieldStyle(.roundedBorder)
                    .controlSize(.large)

                    if let message = model.errorMessage {
                        Label(message, systemImage: "exclamationmark.triangle.fill")
                            .font(.callout)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }

                    Button(action: submit) {
                        if isSubmitting {
                            ProgressView("正在登录…").controlSize(.small)
                        } else {
                            Text("登录")
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    .keyboardShortcut(.defaultAction)
                    .disabled(!canSubmit)
                }
                .frame(maxWidth: 380)
                .padding(Spacing.xxl)
                .frame(maxWidth: .infinity)
            }
            .defaultScrollAnchor(.center, for: .alignment)
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
                        .font(.title2.bold())
                        .accessibilityAddTraits(.isHeader)
                    Text("输入验证器或邮箱中的验证码")
                        .font(.callout)
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
                .font(.system(.title3, design: .monospaced))
                .textContentType(.oneTimeCode)
                .privacySensitive()
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
        Palette.groupedBackground.ignoresSafeArea()
    }
}
