import SwiftUI
import UIShared
import DesignSystem
import Networking

@available(iOS 27.0, *)
struct TwoFactorView: View {
    let model: LoginModel
    @State private var code = ""
    @State private var remember = false
    @State private var provider: TwoFactorProvider
    @Environment(\.dynamicTypeSize) private var typeSize

    private enum Anchor { case code }

    init(model: LoginModel) {
        self.model = model
        _provider = State(initialValue: model.codeProviders.first ?? .authenticator)
    }

    var body: some View {
        ScrollViewReader { reader in
            ScrollView {
                form.onChange(of: code) { _, value in
                    if typeSize.isAccessibilitySize, !value.isEmpty { reader.scrollTo(Anchor.code, anchor: .center) }
                }
            }
            .defaultScrollAnchor(.center, for: .alignment)
            .scrollBounceBehavior(.basedOnSize)
            .scrollDismissesKeyboard(.interactively)
        }
        .background(Palette.groupedBackground)
        .toolbar(.visible, for: .navigationBar)
        .navigationBarTitleDisplayMode(.inline)
        .navigationBarBackButtonHidden(model.isBusy)
        .onChange(of: provider) { _, _ in code = "" }
        .onChange(of: model.codeProviders) { _, offered in
            if !offered.contains(provider), let first = offered.first { provider = first }
        }
    }

    private var form: some View {
        VStack(spacing: Spacing.xl) {
            VStack(spacing: 6) {
                Text("两步验证").font(.title.bold()).accessibilityAddTraits(.isHeader)
                Text(model.codeProviders.isEmpty ? "此服务器要求的验证方式尚不受支持。" :
                        provider == .email ? "输入邮件中的 6 位验证码。" : "打开验证器 App，输入 6 位验证码。")
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
            if !model.codeProviders.isEmpty {
                if model.codeProviders.count > 1 {
                    Picker("验证方式", selection: $provider) {
                        ForEach(model.codeProviders, id: \.self) { Text($0 == .email ? "邮件" : "验证器").tag($0) }
                    }
                    .pickerStyle(.segmented)
                    .frame(maxWidth: 260)
                }
                VerificationCodeField(code: Binding(get: { code }, set: { code = LoginModel.digits(from: $0) }))
                    .onSubmit(verify)
                    .id(Anchor.code)
                OpenVaultCard(padding: 0) {
                    Toggle(UIDevice.current.userInterfaceIdiom == .pad ? "记住这台 iPad" : "记住这台 iPhone", isOn: $remember)
                        .padding(.horizontal, Spacing.lg)
                        .padding(.vertical, Spacing.sm)
                        .frame(minHeight: LayoutMetric.phoneRowHeight)
                }
                if let message = model.errorMessage { LoginMessage(message: message) }
                Button(action: verify) {
                    Text(model.state == .submitting ? "正在验证…" : "验证")
                        .frame(maxWidth: .infinity, minHeight: 44)
                }
                .vaultProminentButtonStyle()
                .buttonBorderShape(.capsule)
                .disabled(code.count != 6)
                .accessibilityIdentifier("twofactor.submit")
                if provider == .email {
                    if model.emailCodeRequested {
                        Text("已请求发送验证码邮件").font(.footnote).foregroundStyle(.secondary)
                    }
                    Button("重新发送邮件") {
                        Task { await model.resendTwoFactorEmail() }
                    }
                    .frame(minHeight: 44)
                }
            }
        }
        .disabled(model.isBusy)
        .frame(maxWidth: 420)
        .padding(20)
        .frame(maxWidth: .infinity)
    }

    private func verify() {
        guard !model.isBusy, code.count == 6 else { return }
        Task { await model.submitTwoFactor(code: code, provider: provider, remember: remember) }
    }
}
