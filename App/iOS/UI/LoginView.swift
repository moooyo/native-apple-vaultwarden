import SwiftUI
import DesignSystem
import Networking
import UIShared

@available(iOS 27.0, *)
public struct LoginView: View {
    @State private var model: LoginModel
    @State private var showingChallenge = false
    @State private var showingServer = false
    @State private var serverDraft = ""
    @State private var revealPassword = false
    @FocusState private var focused: Field?
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    @Environment(\.scenePhase) private var scenePhase
    private let onLoggedIn: (String) -> Void

    private enum Field { case email, password }

    public init(model: LoginModel, onLoggedIn: @escaping (String) -> Void) {
        _model = State(initialValue: model)
        self.onLoggedIn = onLoggedIn
    }

    public var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 0) {
                    OpenVaultMark(size: 64)
                    Text("登录 OpenVault")
                        .font(.title.bold())
                        .accessibilityAddTraits(.isHeader)
                        .padding(.top, Spacing.lg)
                    serverMenu
                        .padding(.top, Spacing.xs)
                    OpenVaultCard(padding: 0) {
                        VStack(spacing: 0) {
                            fieldRow("邮箱") {
                                TextField("name@example.com", text: $model.email)
                                    .textContentType(.username)
                                    .keyboardType(.emailAddress)
                                    .focused($focused, equals: .email)
                                    .submitLabel(.next)
                                    .onSubmit { focused = .password }
                                    .accessibilityLabel("邮箱")
                                    .accessibilityIdentifier("login.email")
                            }
                            Divider().padding(.leading, Spacing.lg)
                            fieldRow("主密码") {
                                HStack(spacing: 0) {
                                    Group {
                                        if revealPassword { TextField("必填", text: $model.password) }
                                        else { SecureField("必填", text: $model.password) }
                                    }
                                    .focused($focused, equals: .password)
                                    .textContentType(.password)
                                    .privacySensitive()
                                    .submitLabel(.go)
                                    .onSubmit(submit)
                                    .accessibilityLabel("主密码")
                                    .accessibilityIdentifier("login.password")
                                    Button {
                                        revealPassword.toggle()
                                        focused = .password
                                    } label: {
                                        Label(revealPassword ? "隐藏主密码" : "显示主密码",
                                              systemImage: revealPassword ? "eye.slash" : "eye")
                                            .labelStyle(.iconOnly)
                                            .frame(minWidth: 44, minHeight: 44)
                                            .contentShape(Rectangle())
                                    }
                                    .foregroundStyle(.secondary)
                                }
                            }
                        }
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    }
                    .disabled(model.isBusy)
                    .padding(.top, Spacing.xl)
                    if let message = model.errorMessage { LoginMessage(message: message).padding(.top, Spacing.sm) }
                    Button(action: submit) {
                        HStack {
                            if model.state == .submitting { ProgressView() }
                            Text(model.state == .submitting ? "正在登录…" : "登录")
                        }
                        .frame(maxWidth: .infinity, minHeight: 44)
                    }
                    .vaultProminentButtonStyle()
                    .buttonBorderShape(.capsule)
                    .disabled(!model.canSubmit)
                    .accessibilityIdentifier("login.submit")
                    .padding(.top, 20)
                    Button {
                        focused = nil
                        Task { await model.requestHint() }
                    } label: {
                        Text(model.hintRecipient.map { "已为 \($0) 请求提示" } ?? "获取主密码提示")
                            .font(.subheadline)
                            .frame(minHeight: 44)
                    }
                    .disabled(!model.canRequestHint || model.hintRecipient != nil)
                    .padding(.top, Spacing.sm)
                }
                .frame(maxWidth: 420)
                .padding(.horizontal, 20)
                .padding(.vertical, Spacing.xl)
                .frame(maxWidth: .infinity)
            }
            .defaultScrollAnchor(.center, for: .alignment)
            .scrollBounceBehavior(.basedOnSize)
            .scrollDismissesKeyboard(.interactively)
            .background(Palette.groupedBackground)
            .toolbar(.hidden, for: .navigationBar)
            .navigationDestination(isPresented: $showingChallenge) { TwoFactorView(model: model) }
        }
        .alert("其他服务器", isPresented: $showingServer) {
            TextField("https://vault.example.com", text: $serverDraft)
                .keyboardType(.URL)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
            Button("取消", role: .cancel) {}
            Button("使用") {
                if let server = ServerEnvironment(string: serverDraft) { model.serverURL = server.base.absoluteString }
            }
            .disabled(ServerEnvironment(string: serverDraft) == nil)
        } message: { Text("输入 Vaultwarden 或 Bitwarden 服务器地址。") }
        .onChange(of: model.isChallenged) { _, active in
            showingChallenge = active
            revealPassword = false
        }
        .onChange(of: showingChallenge) { _, presented in
            if !presented, model.isChallenged { Task { await model.returnToCredentials() } }
        }
        .onChange(of: model.state) { _, state in
            if state == .success { onLoggedIn(model.serverURL) }
        }
        .onChange(of: model.serverURL) { revealPassword = false }
        .onChange(of: scenePhase) { _, phase in if phase != .active { revealPassword = false } }
        .onDisappear {
            if model.isChallenged, !model.isBusy { Task { await model.returnToCredentials() } }
        }
    }

    private var serverMenu: some View {
        Menu {
            if !model.recentServers.isEmpty {
                Picker("服务器", selection: $model.serverURL) {
                    ForEach(model.recentServers, id: \.self) { Text($0).tag($0) }
                    if !model.serverURL.isEmpty, !model.recentServers.contains(model.serverURL) {
                        Text(model.serverURL).tag(model.serverURL)
                    }
                }
                Divider()
            }
            Button("其他服务器…") {
                serverDraft = model.serverURL
                showingServer = true
            }
        } label: {
            HStack(spacing: 6) {
                Text(model.serverLabel).lineLimit(1)
                Image(systemName: "chevron.down").font(.caption.weight(.semibold))
            }
            .font(.subheadline)
            .padding(.horizontal, Spacing.md)
            .padding(.vertical, 6)
            .background(Palette.controlFill, in: .capsule)
            .frame(minHeight: 44)
        }
        .foregroundStyle(.secondary)
        .disabled(model.isBusy)
        .accessibilityLabel("服务器")
        .accessibilityValue(model.serverURL)
    }

    private func fieldRow<Content: View>(_ label: String, @ViewBuilder content: () -> Content) -> some View {
        let layout = dynamicTypeSize.isAccessibilitySize ? AnyLayout(VStackLayout(alignment: .leading, spacing: 2))
            : AnyLayout(HStackLayout(spacing: Spacing.md))
        return layout {
            Text(label)
                .frame(minWidth: 64, alignment: .leading)
                .accessibilityHidden(true)
            content()
        }
        .padding(.horizontal, Spacing.lg)
        .padding(.vertical, Spacing.xs)
        .frame(maxWidth: .infinity, alignment: .leading)
        .frame(minHeight: 52)
    }

    private func submit() {
        guard model.canSubmit else { return }
        focused = nil
        revealPassword = false
        Task { await model.submit() }
    }
}

struct LoginMessage: View {
    let message: String
    var body: some View {
        Label(message, systemImage: "exclamationmark.triangle")
            .font(.footnote)
            .foregroundStyle(.red)
            .frame(maxWidth: .infinity, alignment: .leading)
    }
}
