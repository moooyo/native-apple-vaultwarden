import SwiftUI
import UIShared
import DesignSystem
import Networking

@available(iOS 27.0, *)
public struct TwoFactorView: View {
    let providers: [TwoFactorProvider]
    let isSubmitting: Bool
    let errorMessage: String?
    let onSubmit: (String, TwoFactorProvider, Bool) -> Void
    let onResendEmail: () -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var code = ""
    @State private var rememberDevice = false
    @State private var selectedProvider: TwoFactorProvider
    @FocusState private var codeFocused: Bool

    public init(providers: [TwoFactorProvider], isSubmitting: Bool, errorMessage: String?,
                onResendEmail: @escaping () -> Void,
                onSubmit: @escaping (String, TwoFactorProvider, Bool) -> Void) {
        self.providers = providers
        self.isSubmitting = isSubmitting
        self.errorMessage = errorMessage
        self.onSubmit = onSubmit
        self.onResendEmail = onResendEmail
        _selectedProvider = State(initialValue: providers.first {
            $0 == .authenticator || $0 == .email
        } ?? providers.first ?? .authenticator)
    }

    private var codeEntryProviders: [TwoFactorProvider] {
        providers.filter { $0 == .authenticator || $0 == .email }
    }

    public var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: Spacing.lg) {
                    Image(systemName: "checkmark.shield")
                        .font(.system(size: 44, weight: .medium))
                        .foregroundStyle(Palette.accent)
                        .padding(.top, Spacing.lg)

                    VStack(spacing: Spacing.xs) {
                        Text("验证你的身份")
                            .font(.title2.bold())
                        Text(promptText)
                            .font(.subheadline)
                            .foregroundStyle(Palette.secondaryText)
                            .multilineTextAlignment(.center)
                    }

                    if codeEntryProviders.count > 1 {
                        Picker("验证方式", selection: $selectedProvider) {
                            ForEach(codeEntryProviders, id: \.self) { provider in
                                Text(label(for: provider)).tag(provider)
                            }
                        }
                        .pickerStyle(.segmented)
                    }

                    OpenVaultCard(padding: 0) {
                        VStack(spacing: 0) {
                            TextField("验证码", text: $code)
                                .textContentType(.oneTimeCode)
                                .keyboardType(.numberPad)
                                .font(.system(size: 26, weight: .medium, design: .monospaced))
                                .multilineTextAlignment(.center)
                                .focused($codeFocused)
                                .padding(.horizontal, Spacing.lg)
                                .frame(minHeight: 68)
                            Divider().padding(.leading, Spacing.lg)
                            Toggle("记住这台设备", isOn: $rememberDevice)
                                .padding(.horizontal, Spacing.lg)
                                .frame(minHeight: 54)
                        }
                    }

                    if selectedProvider == .email {
                        Button(action: onResendEmail) {
                            Label("重新发送邮件验证码", systemImage: "envelope.arrow.triangle.branch")
                                .frame(maxWidth: .infinity, minHeight: 44)
                        }
                        .buttonStyle(.bordered)
                        .disabled(isSubmitting)
                    }

                    if let errorMessage {
                        Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                            .font(.subheadline)
                            .foregroundStyle(Palette.danger)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    } else if codeEntryProviders.isEmpty {
                        Label("服务器要求的验证方式尚不受支持。", systemImage: "exclamationmark.triangle")
                            .font(.subheadline)
                            .foregroundStyle(Palette.warning)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }

                    Button {
                        onSubmit(code, selectedProvider, rememberDevice)
                    } label: {
                        Group {
                            if isSubmitting { ProgressView() }
                            else { Text("验证").font(.headline) }
                        }
                        .frame(maxWidth: .infinity, minHeight: 50)
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(code.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                              || isSubmitting || !codeEntryProviders.contains(selectedProvider))
                }
                .padding(Spacing.xl)
                .frame(maxWidth: 520)
                .frame(maxWidth: .infinity)
            }
            .background(Palette.groupedBackground)
            .navigationTitle("两步登录")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("取消") { dismiss() }
                }
            }
            .onAppear { codeFocused = true }
        }
    }

    private var promptText: String {
        switch selectedProvider {
        case .email: "输入邮件中的验证码。"
        case .authenticator: "输入验证器 App 中的验证码。"
        default: "输入你的验证码。"
        }
    }

    private func label(for provider: TwoFactorProvider) -> String {
        switch provider {
        case .authenticator: "验证器"
        case .email: "电子邮件"
        case .yubikey: "YubiKey"
        case .webAuthn: "安全密钥"
        case .duo, .organizationDuo: "Duo"
        case .u2f: "U2F"
        case .remember: "已记住"
        }
    }
}
