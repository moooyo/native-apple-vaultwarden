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

    init(model: LoginModel) {
        self.model = model
        _provider = State(initialValue: model.codeProviders.first ?? .authenticator)
    }

    var body: some View {
        ScrollView {
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
                    OpenVaultCard {
                        Toggle(UIDevice.current.userInterfaceIdiom == .pad ? "记住这台 iPad" : "记住这台 iPhone", isOn: $remember)
                    }
                    if let message = model.errorMessage { LoginMessage(message: message) }
                    Button {
                        Task { await model.submitTwoFactor(code: code, provider: provider, remember: remember) }
                    } label: {
                        Text(model.state == .submitting ? "正在验证…" : "验证")
                            .frame(maxWidth: .infinity, minHeight: 44)
                    }
                    .vaultProminentButtonStyle()
                    .buttonBorderShape(.capsule)
                    .disabled(code.count != 6)
                    .accessibilityIdentifier("twofactor.submit")
                    if provider == .email {
                        Button(model.emailCodeRequested ? "再次发送邮件" : "重新发送邮件") {
                            Task { await model.resendTwoFactorEmail() }
                        }
                        .frame(minHeight: 44)
                    }
                }
            }
            .disabled(model.isBusy)
            .padding(20)
            .frame(maxWidth: 440)
            .frame(maxWidth: .infinity)
        }
        .defaultScrollAnchor(.center, for: .alignment)
        .scrollBounceBehavior(.basedOnSize)
        .background(Palette.groupedBackground)
        .toolbar(.visible, for: .navigationBar)
        .navigationBarTitleDisplayMode(.inline)
        .navigationBarBackButtonHidden(model.isBusy)
        .onChange(of: provider) { _, _ in code = "" }
        .onChange(of: model.codeProviders) { _, offered in
            if !offered.contains(provider), let first = offered.first { provider = first }
        }
    }
}
