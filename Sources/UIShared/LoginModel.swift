import Foundation
import Observation
import Networking
import VaultRepository

@MainActor
@Observable
public final class LoginModel {
    public enum State: Equatable, Sendable {
        case idle, submitting, needsTwoFactor([TwoFactorProvider]), success, error(String)
    }

    public var email = "" { didSet { if email != oldValue { clearFeedback() } } }
    public var password = ""
    public var serverURL: String {
        didSet {
            if serverURL != oldValue {
                if ServerEnvironment(string: oldValue) != ServerEnvironment(string: serverURL) { password = "" }
                clearFeedback()
            }
        }
    }
    public private(set) var state: State = .idle
    public private(set) var recentServers: [String]
    public private(set) var hintRecipient: String?
    public private(set) var emailCodeRequested = false
    public private(set) var sendingMessage = false

    private var challenge: [TwoFactorProvider]?
    private let auth: AuthService
    private let defaults: UserDefaults?
    private static let serverHistoryKey = "openvault.login.recentServers"

    public init(auth: AuthService, serverURL: String = "", defaults: UserDefaults? = .standard) {
        self.auth = auth
        self.defaults = defaults
        let history = (defaults?.stringArray(forKey: Self.serverHistoryKey) ?? [])
            .compactMap { ServerEnvironment(string: $0)?.base.absoluteString }
        let selected = ServerEnvironment(string: serverURL)?.base.absoluteString
        self.serverURL = selected ?? history.first ?? ""
        self.recentServers = Array(((selected.map { [$0] } ?? []) + history.filter { $0 != selected }).prefix(5))
    }

    public var isChallenged: Bool { challenge != nil }
    public var twoFactorProviders: [TwoFactorProvider] { challenge ?? [] }
    public var codeProviders: [TwoFactorProvider] { twoFactorProviders.filter { $0 == .authenticator || $0 == .email } }
    public var serverLabel: String {
        guard let base = ServerEnvironment(string: serverURL)?.base, let host = base.host else { return "选择服务器" }
        return host + (base.port.map { ":\($0)" } ?? "")
    }
    public var isBusy: Bool { state == .submitting || sendingMessage }
    public var validAddress: Bool {
        address.range(of: #"^[^@\s]+@[^@\s]+\.[^@\s]+$"#, options: .regularExpression) != nil
    }
    public var canRequestHint: Bool {
        !isChallenged && !isBusy && validAddress && ServerEnvironment(string: serverURL) != nil
    }
    public var canSubmit: Bool { canRequestHint && !password.isEmpty }
    public var errorMessage: String? {
        if case .error(let message) = state { return message }
        return nil
    }
    private var address: String { email.trimmingCharacters(in: .whitespacesAndNewlines) }

    public static func digits(from text: String) -> String {
        String(text.filter { $0.isASCII && $0.isNumber }.prefix(6))
    }

    public func submit() async {
        guard canSubmit, let server = ServerEnvironment(string: serverURL) else { return }
        serverURL = server.base.absoluteString
        email = address
        state = .submitting
        do { apply(try await auth.login(email: email, password: password, serverURL: serverURL)) }
        catch { state = .error(Self.message(for: error)) }
    }

    public func submitTwoFactor(code: String, provider: TwoFactorProvider? = nil, remember: Bool = false) async {
        guard !isBusy, let chosen = provider ?? codeProviders.first, codeProviders.contains(chosen),
              code.count == 6, Self.digits(from: code) == code else { return }
        state = .submitting
        do {
            apply(try await auth.submitTwoFactor(provider: chosen, code: code, remember: remember, serverURL: serverURL))
        } catch { state = .error(Self.message(for: error)) }
    }

    public func returnToCredentials() async {
        guard isChallenged, !isBusy else { return }
        state = .submitting
        await auth.cancelTwoFactor(email: email, serverURL: serverURL)
        challenge = nil
        emailCodeRequested = false
        state = .idle
    }

    public func resendTwoFactorEmail() async {
        guard !isBusy, twoFactorProviders.contains(.email) else { return }
        sendingMessage = true
        defer { sendingMessage = false }
        do {
            try await auth.sendTwoFactorEmail(serverURL: serverURL)
            emailCodeRequested = true
            state = .needsTwoFactor(twoFactorProviders)
        } catch { state = .error("无法发送验证码，请检查连接后重试。") }
    }

    public func requestHint() async {
        guard canRequestHint else { return }
        let recipient = address
        let server = serverURL
        sendingMessage = true
        defer { sendingMessage = false }
        do {
            try await auth.requestPasswordHint(email: recipient, serverURL: server)
            guard recipient == address, server == serverURL else { return }
            hintRecipient = recipient
            state = .idle
        } catch {
            guard recipient == address, server == serverURL else { return }
            state = .error("未能获取密码提示，请检查服务器设置或稍后再试。")
        }
    }

    private func clearFeedback() {
        hintRecipient = nil
        if !isChallenged, case .error = state { state = .idle }
    }

    private func apply(_ result: LoginResult) {
        password = ""
        switch result {
        case .success:
            challenge = nil
            recentServers = Array(([serverURL] + recentServers.filter { $0 != serverURL }).prefix(5))
            defaults?.set(recentServers, forKey: Self.serverHistoryKey)
            state = .success
        case .twoFactorRequired(let providers):
            let wasChallenged = isChallenged
            challenge = providers
            state = wasChallenged ? .error("验证码未通过验证，请输入新的验证码。") : .needsTwoFactor(providers)
        }
    }
}
