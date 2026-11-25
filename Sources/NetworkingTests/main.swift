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
    checkWebAuthnSecondFactor(&r)
    await checkDeviceLoginTransport(&r)
    await checkSendEmailLoginCode(&r)
    await checkPasswordHintRequest(&r)
    await checkTokenTwoFactorRetry(&r)
    await checkTokenBadCredentials(&r)
    await checkRefresh(&r)
    await checkInFlightRefreshLeaseRevocation(&r)
    await checkStagedRefresh(&r)

    // Vault / api
    await checkSync(&r)
    await checkAccountScopedVaultRequests(&r)
    await checkCipherVisibilityRequests(&r)
    await checkInFlightAccountLeaseRevocation(&r)
    await checkBearerRotationPreservesAccountLease(&r)
    await checkHeaderInjection(&r)
    await checkSecureTransportFirstHop(&r)
    await checkReturnedResponseDestinations(&r)
    await checkRequestDestinationPolicy(&r)
    checkWebsiteIconLocation(&r)
    await checkWebsiteIconClient(&r)
    await checkWebsiteIconRequestPermission(&r)
    await checkWebsiteIconQueuedPermission(&r)
    await checkWebsiteIconInvalidation(&r)
    #if os(macOS)
    await checkLoopbackRedirects(&r)
    #endif
    await checkCipherCRUD(&r)
    await checkCipherWriterProfileLookup(&r)
    await checkCipherProfileLookupLeaseRevocation(&r)
    await checkCipherCreateAcknowledgment(&r)
    await checkCipherCreateDispatchLeaseRevocation(&r)
    checkCompleteCipherRequestEncoding(&r)
    await checkFolders(&r)
    await checkAttachments(&r)
    await checkSendRequests(&r)
    await checkConfigAndAlive(&r)
    await checkErrorMapping(&r)
    await checkDevicePushNoOp(&r)

    return r.summary()
}

let failures = await runAllTests()
if failures != 0 { exit(1) }
