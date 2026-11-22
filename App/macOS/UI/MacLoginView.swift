import SwiftUI
import UIShared
import DesignSystem
import Networking

public struct MacLoginView: View {
    @State private var model: LoginModel
    @State private var code = ""
    @State private var provider: TwoFactorProvider = .authenticator
    @State private var remember = false
    @State private var revealPassword = false
    @State private var showHelp = false
    @FocusState private var focus: Field?
    private let onLoggedIn: (String) -> Void

    private enum Field { case email, server, password }

    public init(model: LoginModel, onLoggedIn: @escaping (String) -> Void) {
        _model = State(initialValue: model)
        self.onLoggedIn = onLoggedIn
    }

    public var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(spacing: Spacing.lg) {
                    OpenVaultMark(size: 64)
                    Text(model.isChallenged ? "两步验证" : "登录 OpenVault")
                        .font(.title2.bold()).accessibilityAddTraits(.isHeader)
                    if model.isChallenged { challengeFields } else { credentials }
                    if let message = model.errorMessage {
                        Label(message, systemImage: "exclamationmark.triangle")
                            .font(.callout).foregroundStyle(.red)
                    }
                }
                .frame(maxWidth: 340)
                .frame(maxWidth: .infinity)
                .padding(Spacing.lg)
                .disabled(model.isBusy)
            }
            .defaultScrollAnchor(.center, for: .alignment)
            HStack {
                Button("帮助", systemImage: "questionmark.circle") { showHelp = true }
                    .labelStyle(.iconOnly)
                    .buttonStyle(.borderless)
                    .popover(isPresented: $showHelp) {
                        Text(model.isChallenged ? "从服务器提供的方式中选择一项，然后输入 6 位验证码。" : "输入你的邮箱、保险库服务器地址和主密码。服务器地址可向管理员索取。")
                            .font(.callout).padding(Spacing.lg).frame(width: 280)
                    }
                Spacer()
                if model.isChallenged {
                    Button("返回") { Task { await model.returnToCredentials() } }
                        .keyboardShortcut(.cancelAction)
                        .disabled(model.isBusy)
                }
                Button(action: submit) {
                    HStack {
                        if model.state == .submitting { ProgressView().controlSize(.small) }
                        Text(model.isChallenged ? (model.state == .submitting ? "正在验证…" : "验证") :
                                (model.state == .submitting ? "正在登录…" : "登录"))
                            .frame(minWidth: 64)
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!canSubmit)
                .accessibilityIdentifier(model.isChallenged ? "twofactor.submit" : "login.submit")
            }
            .padding(Spacing.md)
        }
        .background(Palette.groupedBackground)
        .onChange(of: model.codeProviders) { _, offered in
            if !offered.contains(provider), let first = offered.first { provider = first }
        }
        .onChange(of: provider) { _, _ in code = "" }
        .onChange(of: model.isChallenged) { _, active in
            code = ""
            remember = false
            revealPassword = false
            if !active { focus = .password }
        }
        .onChange(of: model.state) { _, state in if state == .success { onLoggedIn(model.serverURL) } }
        .onDisappear {
            if model.isChallenged, !model.isBusy { Task { await model.returnToCredentials() } }
        }
    }

    private var credentials: some View {
        VStack(spacing: Spacing.md) {
            TextField("邮箱地址", text: $model.email)
                .focused($focus, equals: .email)
                .textContentType(.username)
                .onSubmit { focus = .server }
                .accessibilityIdentifier("login.email")
            HStack {
                TextField("服务器地址", text: $model.serverURL, prompt: Text("https://vault.example.com"))
                    .focused($focus, equals: .server)
                    .onSubmit { focus = .password }
                Menu("最近使用的服务器", systemImage: "chevron.down") {
                    if !model.recentServers.isEmpty {
                        ForEach(model.recentServers, id: \.self) { server in
                            Button { model.serverURL = server } label: {
                                if server == model.serverURL { Label(server, systemImage: "checkmark") }
                                else { Text(server) }
                            }
                        }
                        Divider()
                    }
                    Button("其他服务器…") { focus = .server }
                }
                .menuStyle(.borderlessButton).labelStyle(.iconOnly).fixedSize()
            }
            HStack {
                Group {
                    if revealPassword { TextField("主密码", text: $model.password) }
                    else { SecureField("主密码", text: $model.password) }
                }
                .focused($focus, equals: .password)
                .privacySensitive()
                .textContentType(.password)
                .onSubmit(submit)
                .accessibilityIdentifier("login.password")
                Button(revealPassword ? "隐藏主密码" : "显示主密码", systemImage: revealPassword ? "eye.slash" : "eye") {
                    revealPassword.toggle()
                    focus = .password
                }
                .labelStyle(.iconOnly).buttonStyle(.borderless)
            }
            Button(model.hintRecipient.map { "已为 \($0) 请求提示" } ?? "获取主密码提示") {
                Task { await model.requestHint() }
            }
            .buttonStyle(.link)
            .frame(maxWidth: .infinity, alignment: .trailing)
            .disabled(!model.canRequestHint || model.hintRecipient != nil)
        }
        .textFieldStyle(.roundedBorder)
        .controlSize(.large)
        .autocorrectionDisabled()
    }

    @ViewBuilder private var challengeFields: some View {
        if model.codeProviders.isEmpty {
            Text("此服务器要求的验证方式尚不受支持。").foregroundStyle(.secondary)
        } else {
            Text(provider == .email ? "输入邮件中的 6 位验证码。" : "打开验证器 App，输入 6 位验证码。")
                .foregroundStyle(.secondary)
            if model.codeProviders.count > 1 {
                Picker("验证方式", selection: $provider) {
                    ForEach(model.codeProviders, id: \.self) { Text($0 == .email ? "邮件" : "验证器").tag($0) }
                }
                .labelsHidden().pickerStyle(.segmented).frame(maxWidth: 200)
            }
            VerificationCodeField(code: Binding(get: { code }, set: { code = LoginModel.digits(from: $0) }))
                .frame(maxWidth: 260).onSubmit(submit)
            HStack(spacing: Spacing.lg) {
                Toggle("记住这台 Mac", isOn: $remember).toggleStyle(.checkbox)
                if provider == .email {
                    Button(model.emailCodeRequested ? "再次发送邮件" : "重新发送邮件") {
                        Task { await model.resendTwoFactorEmail() }
                    }
                    .buttonStyle(.link)
                }
            }
        }
    }

    private var canSubmit: Bool {
        model.isChallenged ? !model.isBusy && model.codeProviders.contains(provider) && code.count == 6 : model.canSubmit
    }

    private func submit() {
        guard canSubmit else { return }
        revealPassword = false
        if model.isChallenged { Task { await model.submitTwoFactor(code: code, provider: provider, remember: remember) } }
        else { Task { await model.submit() } }
    }
}

struct OpenVaultLockBackground: View {
    var body: some View { Palette.groupedBackground.ignoresSafeArea() }
}
