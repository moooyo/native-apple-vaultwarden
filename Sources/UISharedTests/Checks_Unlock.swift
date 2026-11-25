import Foundation
import VaultModels
import Networking
import VaultRepository
import UIShared

@MainActor
func checkUnlockLogoutFailure(_ runner: inout TestRunner) async {
    let email = "locked-fixture@example.test"
    let auth = FakeAuthService(email: email)
    let model = UnlockModel(auth: auth)
    await model.loadAccount()
    await auth.setLogoutSucceeds(false)
    runner.expectTrue(!(await model.logout()), "failed logout does not report success")
    runner.expectTrue(model.errorMessage != nil && model.email == email, "failed logout keeps the locked account visible")
    await auth.setLogoutSucceeds(true)
    runner.expectTrue(await model.logout(), "retry reports a successful logout")
    runner.expectTrue(model.state == .locked && model.email == nil, "successful logout clears the account")
}

@MainActor
func checkUnlockPasswordSuccess(_ r: inout TestRunner) async {
    let auth = FakeAuthService()
    let model = UnlockModel(auth: auth)
    r.expect(model.state, .locked, "Unlock: initial state is .locked")

    model.password = "correct horse"
    await model.unlockWithPassword()

    r.expect(model.state, .unlocked, "Unlock: success → .unlocked")
    r.expect(model.password, "", "Unlock: password field cleared on success")
    let unlocked = await auth.isUnlocked()
    r.expectTrue(unlocked, "Unlock: underlying service is unlocked")
    let calls = await auth.unlockMasterCalls
    r.expect(calls, ["correct horse"], "Unlock: master password forwarded")
}

@MainActor
func checkUnlockPasswordError(_ r: inout TestRunner) async {
    let auth = FakeAuthService()
    await auth.setUnlockMasterError(RepositoryError.authenticationFailed)
    let model = UnlockModel(auth: auth)

    model.password = "wrong"
    await model.unlockWithPassword()

    // Stays locked; surfaces an error message.
    if case .error(let message) = model.state {
        r.expectTrue(!message.isEmpty, "Unlock: error message non-empty")
    } else {
        r.expectTrue(false, "Unlock: wrong password → .error (got \(model.state))")
    }
    r.expectNotNil(model.errorMessage, "Unlock: errorMessage exposed")
    r.expect(model.password, "", "Unlock: password cleared on failure")
    let unlocked = await auth.isUnlocked()
    r.expectFalse(unlocked, "Unlock: service stays locked on error")
}

@MainActor
func checkUnlockPasswordWhilePending(_ r: inout TestRunner) async {
    let enteredPassword = "fixture password"
    for cancelled in [false, true] {
        let gate = PausedAuthSubmission()
        let auth = FakeAuthService(submissionGate: gate)
        if cancelled { await auth.setUnlockMasterError(RepositoryError.authenticationFailed) }
        let model = UnlockModel(auth: auth)
        model.password = enteredPassword

        let attempt = Task { await model.unlockWithPassword() }
        await gate.waitUntilStarted()
        r.expect(model.password, "", "Unlock: submitted password is cleared before the service finishes")
        if cancelled { attempt.cancel() }
        else { model.password = enteredPassword }
        await gate.finish()
        await attempt.value

        r.expect(model.state, cancelled ? .locked : .unlocked, "Unlock: completion state matches the outcome")
        r.expect(model.password, cancelled ? "" : enteredPassword, "Unlock: cancellation stays clear and success does not erase replacement input")
    }
}

@MainActor
func checkUnlockBiometricsSuccess(_ r: inout TestRunner) async {
    let auth = FakeAuthService()
    let model = UnlockModel(auth: auth)
    model.password = "unused fixture credential"

    await model.unlockWithBiometrics(reason: "Test")

    r.expect(model.state, .unlocked, "Unlock(bio): success → .unlocked")
    r.expect(model.password, "", "Unlock(bio): clears any typed master password on success")
    let calls = await auth.biometricCalls
    r.expect(calls, ["Test"], "Unlock(bio): reason forwarded")
}

@MainActor
func checkUnlockBiometricsError(_ r: inout TestRunner) async {
    let auth = FakeAuthService()
    await auth.setUnlockBiometricsError(RepositoryError.authenticationFailed)
    let model = UnlockModel(auth: auth)
    model.password = "unused fixture credential"

    await model.unlockWithBiometrics()

    r.expect(model.password, "", "Unlock(bio): failure clears unused master-password input")
    if case .error = model.state {
        r.expectTrue(true, "Unlock(bio): failure → .error")
    } else {
        r.expectTrue(false, "Unlock(bio): failure → .error (got \(model.state))")
    }
}
