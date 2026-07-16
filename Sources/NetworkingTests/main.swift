import Foundation
import Networking

func runAllTests() async -> Int {
    var r = TestRunner()

    // ServerEnvironment (synchronous)
    checkServerEnvironment(&r)

    // Identity / auth
    await checkPrelogin(&r)
    await checkEnvironmentSwitch(&r)
    await checkAccountScopedContextClear(&r)
    await checkTokenSuccess(&r)
    await checkTokenPasswordHashSpecialChars(&r)
    await checkTokenTwoFactor(&r)
    await checkSendEmailLoginCode(&r)
    await checkTokenTwoFactorRetry(&r)
    await checkTokenBadCredentials(&r)
    await checkRefresh(&r)
    await checkInFlightRefreshLeaseRevocation(&r)

    // Vault / api
    await checkSync(&r)
    await checkAccountScopedVaultRequests(&r)
    await checkInFlightAccountLeaseRevocation(&r)
    await checkBearerRotationPreservesAccountLease(&r)
    await checkHeaderInjection(&r)
    await checkCipherCRUD(&r)
    checkCompleteCipherRequestEncoding(&r)
    await checkFolders(&r)
    await checkAttachments(&r)
    await checkConfigAndAlive(&r)
    await checkErrorMapping(&r)
    await checkDevicePushNoOp(&r)

    return r.summary()
}

let failures = await runAllTests()
if failures != 0 { exit(1) }
