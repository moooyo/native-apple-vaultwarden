import Foundation
import VaultModels
import Networking
import VaultRepository
import UIShared

@MainActor
func checkLoginSuccess(_ r: inout TestRunner) async {
    let auth = FakeAuthService(loginResults: [.success(.success)])
    let model = LoginModel(auth: auth, serverURL: "https://vault.example.com", defaults: nil)
    model.email = "user@example.com"
    let enteredPassword = "  p\u{0301}w \n"
    model.password = enteredPassword

    await model.submit()

    r.expect(model.state, .success, "Login: success → .success")
    r.expect(model.password, "", "Login: password cleared on success")
    let calls = await auth.loginCalls
    r.expect(calls.count, 1, "Login: login called once")
    r.expect(calls.first?.email, "user@example.com", "Login: email forwarded")
    r.expect(calls.first.map { Array($0.password.utf8) }, Array(enteredPassword.utf8), "Login: password bytes forwarded unchanged")
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
    let model = LoginModel(auth: auth, serverURL: "https://vault.example.com", defaults: nil)
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
    let model = LoginModel(auth: auth, serverURL: "https://vault.example.com", defaults: nil)
    model.email = "u@e.com"; model.password = "bad"

    await model.submit()

    if case .error = model.state {
        r.expectTrue(true, "Login: failure → .error")
    } else {
        r.expectTrue(false, "Login: failure → .error (got \(model.state))")
    }
    r.expectNotNil(model.errorMessage, "Login: errorMessage exposed")
    r.expect(model.password, "", "Login: password cleared on failure")
}

@MainActor
func checkLoginPasswordWhilePending(_ r: inout TestRunner) async {
    let enteredPassword = "fixture password"
    for cancelled in [false, true] {
        let gate = PausedAuthSubmission()
        let result: Result<LoginResult, Error> = cancelled
            ? .failure(RepositoryError.underlying(kind: .network, description: "Cancelled request"))
            : .success(.success)
        let auth = FakeAuthService(loginResults: [result], submissionGate: gate)
        let model = LoginModel(auth: auth, serverURL: "https://vault.example.com", defaults: nil)
        model.email = "user@example.com"
        model.password = enteredPassword

        let attempt = Task { await model.submit() }
        await gate.waitUntilStarted()
        r.expect(model.password, "", "Login: submitted password is cleared before the service finishes")
        if cancelled { attempt.cancel() }
        else { model.password = enteredPassword }
        await gate.finish()
        await attempt.value

        r.expect(model.state, cancelled ? .idle : .success, "Login: completion state matches the outcome")
        r.expect(model.password, cancelled ? "" : enteredPassword, "Login: cancellation stays clear and success does not erase replacement input")
    }
}

@MainActor
func checkLoginUnsupportedKDFMessage(_ r: inout TestRunner) async {
    let auth = FakeAuthService(loginResults: [.failure(RepositoryError.unsupportedKDF(1))])
    let model = LoginModel(auth: auth, serverURL: "https://vault.example.com", defaults: nil)
    model.email = "u@e.com"; model.password = "pw"

    await model.submit()

    if case .error(let message) = model.state {
        r.expectTrue(message.contains("Argon2id"), "Login: unsupported KDF message mentions Argon2id")
    } else {
        r.expectTrue(false, "Login: unsupported KDF → .error")
    }
}

@MainActor
func checkLoginKDFBoundsMessages(_ r: inout TestRunner) async {
    let descriptions = ["insufficientKdfParameters", "excessiveKdfParameters", "private diagnostic details"]
    let auth = FakeAuthService(loginResults: descriptions.map {
        .failure(RepositoryError.underlying(kind: .crypto, description: $0))
    })
    let model = LoginModel(auth: auth, serverURL: "https://vault.example.com", defaults: nil)
    model.email = "user@example.com"
    var messages: [String] = []
    for description in descriptions {
        model.password = "fixture password"
        await model.submit()
        r.expectNotNil(model.errorMessage, "Login: wrapped crypto failure shows an error")
        let message = model.errorMessage ?? ""
        r.expectFalse(message.contains(description), "Login: wrapped crypto error does not echo raw diagnostics")
        messages.append(message)
    }
    r.expectTrue(messages[0].contains("PBKDF2") && messages[1].contains("PBKDF2"), "Login: both unsupported counts point to PBKDF2 settings")
    r.expectTrue(messages[0] != messages[1], "Login: too few rounds and too many rounds have distinct messages")
    r.expectFalse(messages[2].contains("PBKDF2"), "Login: unrelated crypto error uses generic copy")
}

@MainActor
func checkChallengeRetryAndCancellation(_ runner: inout TestRunner) async {
    let auth = FakeAuthService(loginResults: [
        .success(.twoFactorRequired([.authenticator, .email])),
        .failure(RepositoryError.authenticationFailed)
    ])
    let model = LoginModel(auth: auth, serverURL: "https://vault.example.test", defaults: nil)
    model.email = "malformed"
    model.password = "a password"
    await model.submit()
    runner.expect(await auth.loginCalls.count, 0, "Invalid email does not submit")
    model.email = " alice@example.test "
    await model.requestHint()
    runner.expect(await auth.hintRequests, ["alice@example.test"], "Password hint uses only the trimmed email")
    await model.submit()
    runner.expect(model.password, "", "A challenge no longer retains the password in the form")
    await model.submitTwoFactor(code: "12345")
    await model.submitTwoFactor(code: "12x456")
    await model.submitTwoFactor(code: "123456", provider: .duo)
    runner.expect(await auth.twoFactorCalls.count, 0, "Only an offered provider with six digits can submit")
    await model.submitTwoFactor(code: "123456", provider: .email, remember: true)
    runner.expect(model.codeProviders, [.authenticator, .email], "A rejected code keeps the offered methods for retry")
    runner.expectNotNil(model.errorMessage, "A rejected code shows an error on the challenge")
    await model.resendTwoFactorEmail()
    runner.expect(await auth.emailCodeRequests, [model.serverURL], "Resend remains available after rejection")
    await model.returnToCredentials()
    runner.expect(model.state, .idle, "Back returns to credentials")
    runner.expect(model.password, "", "Back does not restore the previously submitted password")
    runner.expect(await auth.cancelledChallenges, ["alice@example.test"], "Back abandons the pending challenge")
    runner.expect(model.codeProviders, [], "Back clears the old challenge")
}

@MainActor
func checkRecentServers(_ runner: inout TestRunner) async {
    let suite = "openvault.login.test.\(UUID().uuidString)"
    guard let defaults = UserDefaults(suiteName: suite) else { return }
    defer { defaults.removePersistentDomain(forName: suite) }
    let auth = FakeAuthService(loginResults: [.success(.success)])
    let first = LoginModel(auth: auth, defaults: defaults)
    first.email = "alice@example.test"
    first.password = "a password"
    first.serverURL = "https://user:secret@vault.example.test"
    runner.expectFalse(first.canSubmit, "A deployment URL cannot contain credentials")
    first.serverURL = "https://vault.example.test/site/"
    runner.expect(first.password, "", "Changing the destination clears credentials entered for another server")
    first.password = "a password"
    await first.submit()
    let next = LoginModel(auth: auth, defaults: defaults)
    runner.expect(next.recentServers, ["https://vault.example.test/site"], "Only the successful canonical deployment is persisted")
    runner.expect(next.serverURL, "https://vault.example.test/site", "A new form selects the last deployment")
    runner.expect(next.email, "", "Server history does not persist email")
    runner.expect(next.password, "", "Server history does not persist passwords")
}
