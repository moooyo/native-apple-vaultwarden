import Foundation
import Observation
import Networking
import VaultRepository

/// Drives the login screen: collect email / password / server URL, submit, and walk the
/// optional 2FA round-trip. Logic only — no SwiftUI.
@MainActor
@Observable
public final class LoginModel {
    /// The login lifecycle the view renders from.
    public enum State: Equatable, Sendable {
        case idle
        case submitting
        /// The server demanded a second factor; the view shows a code field for one of
        /// `providers`. The chosen provider + code go back via `submitTwoFactor`.
        case needsTwoFactor([TwoFactorProvider])
        case success
        case error(String)
    }

    // Bound fields.
    public var email: String = ""
    public var password: String = ""
    public var serverURL: String = ""

    public private(set) var state: State = .idle

    private let auth: AuthService

    public init(auth: AuthService, serverURL: String = "") {
        self.auth = auth
        self.serverURL = serverURL
    }

    /// The 2FA providers offered by the server, if a challenge is in flight.
    public var twoFactorProviders: [TwoFactorProvider] {
        if case .needsTwoFactor(let providers) = state { return providers }
        return []
    }

    public var errorMessage: String? {
        if case .error(let message) = state { return message }
        return nil
    }

    /// Submit the entered credentials. Routes to `.success`, `.needsTwoFactor`, or `.error`.
    public func submit() async {
        guard state != .submitting else { return }
        state = .submitting
        do {
            let result = try await auth.login(email: email, password: password, serverURL: serverURL)
            apply(result)
        } catch {
            state = .error(Self.message(for: error))
        }
    }

    /// Answer the 2FA challenge with a code. Uses the first offered provider unless one is
    /// given explicitly. Routes to `.success` or `.error`; a fresh challenge stays in
    /// `.needsTwoFactor`.
    public func submitTwoFactor(code: String, provider: TwoFactorProvider? = nil,
                                remember: Bool = false) async {
        let chosen = provider ?? twoFactorProviders.first ?? .authenticator
        state = .submitting
        do {
            let result = try await auth.submitTwoFactor(provider: chosen, code: code,
                                                        remember: remember, serverURL: serverURL)
            apply(result)
        } catch {
            state = .error(Self.message(for: error))
        }
    }

    private func apply(_ result: LoginResult) {
        switch result {
        case .success:
            password = ""
            state = .success
        case .twoFactorRequired(let providers):
            state = .needsTwoFactor(providers)
        }
    }
}
