import SwiftUI
import UIShared
import DesignSystem
import VaultRepository
import Networking

@available(iOS 27.0, *)
public struct LoginView: View {
    @State private var model: LoginModel
    @State private var showTwoFactor = false
    @FocusState private var focusedField: Field?
    private let onLoggedIn: (String) -> Void

    private enum Field { case server, email, password }

    public init(model: LoginModel, onLoggedIn: @escaping (String) -> Void) {
        _model = State(initialValue: model)
        self.onLoggedIn = onLoggedIn
    }

    private var isSubmitting: Bool { model.state == .submitting }
    private var canSubmit: Bool {
        !model.serverURL.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        && !model.email.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        && !model.password.isEmpty && !isSubmitting
    }

    public var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: Spacing.lg) {
                    VStack(spacing: Spacing.md) {
                        OpenVaultMark(size: 76)
                        VStack(spacing: Spacing.xs) {
                            Text("欢迎使用 OpenVault")
                                .font(.title2.bold())
                            Text("连接 Bitwarden 或 Vaultwarden 保险库")
                                .font(.subheadline)
                                .foregroundStyle(Palette.secondaryText)
                        }
                    }
                    .padding(.top, Spacing.xl)

                    OpenVaultCard(padding: 0) {
                        VStack(spacing: 0) {
                            loginField("服务器地址", prompt: "https://vault.example.com",
                                       text: $model.serverURL, field: .server,
                                       contentType: .URL, keyboard: .URL)
                            Divider().padding(.leading, Spacing.lg)
                            loginField("邮箱", prompt: "name@example.com",
                                       text: $model.email, field: .email,
                                       contentType: .username, keyboard: .emailAddress)
                            Divider().padding(.leading, Spacing.lg)
                            VStack(alignment: .leading, spacing: Spacing.xxs) {
                                Text("主密码")
                                    .font(Typography.fieldLabel)
                                    .foregroundStyle(Palette.secondaryText)
                                SecureField("输入主密码", text: $model.password)
                                    .textContentType(.password)
                                    .focused($focusedField, equals: .password)
                                    .submitLabel(.go)
                                    .onSubmit { submit() }
                            }
                            .padding(.horizontal, Spacing.lg)
                            .padding(.vertical, Spacing.sm)
                            .frame(minHeight: 66)
                        }
                    }

                    if let message = model.errorMessage {
                        Label(message, systemImage: "exclamationmark.triangle.fill")
                            .font(.subheadline)
                            .foregroundStyle(Palette.danger)
                            .padding(Spacing.md)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(Palette.danger.opacity(0.1),
                                        in: RoundedRectangle(cornerRadius: CornerRadius.md,
                                                             style: .continuous))
                    }

                    Button(action: submit) {
                        Group {
                            if isSubmitting { ProgressView() }
                            else { Text("登录").font(.headline) }
                        }
                        .frame(maxWidth: .infinity, minHeight: 50)
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(!canSubmit)

                    Label("主密码仅用于验证与解密，且不会写入应用日志。",
                          systemImage: "lock.shield")
                        .font(.caption)
                        .foregroundStyle(Palette.secondaryText)
                }
                .padding(Spacing.xl)
                .frame(maxWidth: 560)
                .frame(maxWidth: .infinity)
            }
            .background(Palette.groupedBackground)
            .scrollDismissesKeyboard(.interactively)
            .navigationTitle("登录")
            .navigationBarTitleDisplayMode(.inline)
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
            TwoFactorView(
                providers: model.twoFactorProviders,
                isSubmitting: isSubmitting,
                errorMessage: model.errorMessage
            ) { code, provider, remember in
                Task { await model.submitTwoFactor(code: code, provider: provider, remember: remember) }
            }
            .interactiveDismissDisabled(true)
            .presentationDetents([.medium, .large])
            .presentationDragIndicator(.visible)
        }
    }

    private func loginField(_ label: String, prompt: String, text: Binding<String>,
                            field: Field, contentType: UITextContentType?,
                            keyboard: UIKeyboardType) -> some View {
        VStack(alignment: .leading, spacing: Spacing.xxs) {
            Text(label)
                .font(Typography.fieldLabel)
                .foregroundStyle(Palette.secondaryText)
            TextField(prompt, text: text)
                .textContentType(contentType)
                .keyboardType(keyboard)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .focused($focusedField, equals: field)
                .submitLabel(field == .server ? .next : .next)
                .onSubmit { focusedField = field == .server ? .email : .password }
        }
        .padding(.horizontal, Spacing.lg)
        .padding(.vertical, Spacing.sm)
        .frame(minHeight: 66)
    }

    private func submit() {
        guard canSubmit else { return }
        focusedField = nil
        Task { await model.submit() }
    }
}
