import Foundation
import VaultModels
import Networking
import VaultRepository
import UIShared

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
    let unlocked = await auth.isUnlocked()
    r.expectFalse(unlocked, "Unlock: service stays locked on error")
}

@MainActor
func checkUnlockBiometricsSuccess(_ r: inout TestRunner) async {
    let auth = FakeAuthService()
    let model = UnlockModel(auth: auth)

    await model.unlockWithBiometrics(reason: "Test")

    r.expect(model.state, .unlocked, "Unlock(bio): success → .unlocked")
    let calls = await auth.biometricCalls
    r.expect(calls, ["Test"], "Unlock(bio): reason forwarded")
}

@MainActor
func checkUnlockBiometricsError(_ r: inout TestRunner) async {
    let auth = FakeAuthService()
    await auth.setUnlockBiometricsError(RepositoryError.authenticationFailed)
    let model = UnlockModel(auth: auth)

    await model.unlockWithBiometrics()

    if case .error = model.state {
        r.expectTrue(true, "Unlock(bio): failure → .error")
    } else {
        r.expectTrue(false, "Unlock(bio): failure → .error (got \(model.state))")
    }
}
