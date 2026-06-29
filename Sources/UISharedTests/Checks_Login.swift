import Foundation
import VaultModels
import Networking
import VaultRepository
import UIShared

@MainActor
func checkLoginSuccess(_ r: inout TestRunner) async {
    let auth = FakeAuthService(loginResults: [.success(.success)])
    let model = LoginModel(auth: auth, serverURL: "https://vault.example.com")
    model.email = "user@example.com"
    model.password = "pw"

    await model.submit()

    r.expect(model.state, .success, "Login: success → .success")
    r.expect(model.password, "", "Login: password cleared on success")
    let calls = await auth.loginCalls
    r.expect(calls.count, 1, "Login: login called once")
    r.expect(calls.first?.email, "user@example.com", "Login: email forwarded")
    r.expect(calls.first?.server, "https://vault.example.com", "Login: server URL forwarded")
}

@MainActor
func checkLoginNeedsTwoFactorThenSuccess(_ r: inout TestRunner) async {
    // First login → 2FA required (authenticator + email); then submitTwoFactor → success.
    let providers: [TwoFactorProvider] = [.authenticator, .email]
    let auth = FakeAuthService(loginResults: [
        .success(.twoFactorRequired(providers)),
        .success(.success),
    ])
    let model = LoginModel(auth: auth, serverURL: "https://vault.example.com")
    model.email = "u@e.com"
    model.password = "pw"

    await model.submit()

    r.expect(model.state, .needsTwoFactor(providers), "Login: 2FA required state")
    r.expect(model.twoFactorProviders, providers, "Login: providers exposed")

    await model.submitTwoFactor(code: "123456")

    r.expect(model.state, .success, "Login: 2FA success → .success")
    let tfCalls = await auth.twoFactorCalls
    r.expect(tfCalls.count, 1, "Login: submitTwoFactor called once")
    r.expect(tfCalls.first?.code, "123456", "Login: 2FA code forwarded")
    r.expect(tfCalls.first?.provider, .authenticator, "Login: defaults to first offered provider")
}

@MainActor
func checkLoginError(_ r: inout TestRunner) async {
    let auth = FakeAuthService(loginResults: [.failure(RepositoryError.authenticationFailed)])
    let model = LoginModel(auth: auth, serverURL: "https://vault.example.com")
    model.email = "u@e.com"; model.password = "bad"

    await model.submit()

    if case .error = model.state {
        r.expectTrue(true, "Login: failure → .error")
    } else {
        r.expectTrue(false, "Login: failure → .error (got \(model.state))")
    }
    r.expectNotNil(model.errorMessage, "Login: errorMessage exposed")
}

@MainActor
func checkLoginUnsupportedKDFMessage(_ r: inout TestRunner) async {
    let auth = FakeAuthService(loginResults: [.failure(RepositoryError.unsupportedKDF(1))])
    let model = LoginModel(auth: auth, serverURL: "https://vault.example.com")
    model.email = "u@e.com"; model.password = "pw"

    await model.submit()

    if case .error(let message) = model.state {
        r.expectTrue(message.contains("Argon2id"), "Login: unsupported KDF message mentions Argon2id")
    } else {
        r.expectTrue(false, "Login: unsupported KDF → .error")
    }
}
