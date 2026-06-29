import Foundation
import Networking

func runAllTests() async -> Int {
    var r = TestRunner()

    // ServerEnvironment (synchronous)
    checkServerEnvironment(&r)

    // Identity / auth
    await checkPrelogin(&r)
    await checkTokenSuccess(&r)
    await checkTokenTwoFactor(&r)
    await checkTokenTwoFactorRetry(&r)
    await checkTokenBadCredentials(&r)
    await checkRefresh(&r)

    // Vault / api
    await checkSync(&r)
    await checkHeaderInjection(&r)
    await checkCipherCRUD(&r)
    await checkFolders(&r)
    await checkAttachments(&r)
    await checkConfigAndAlive(&r)
    await checkErrorMapping(&r)
    await checkDevicePushNoOp(&r)

    return r.summary()
}

let failures = await runAllTests()
if failures != 0 { exit(1) }
