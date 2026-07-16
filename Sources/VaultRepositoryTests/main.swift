import Foundation
import VaultRepository

/// Headless test runner for VaultRepository (no XCTest on this CLT host).
/// Exercises the auth (login / 2FA / unlock), vault CRUD, lock, and DI-container paths
/// end-to-end against a fake AuthAPI/VaultAPI + a real KeyVault + a temp-DB VaultStore +
/// in-memory KeychainBridge seams.
func runAllTests() async -> Int {
    var r = TestRunner()

    // Login pipeline: happy path (PBKDF2), Argon2id rejection (D6), 2FA round-trip.
    await checkLoginHappyPath(&r)
    await checkConcurrentLoginSupersession(&r)
    await checkLoginTransitionWithdrawsActiveMarker(&r)
    await checkLogoutSupersedesLoginCommit(&r)
    await checkNewLoginSupersedesSuspendedLogout(&r)
    await checkSameAccountLoginWaitsForLogoutCleanup(&r)
    await checkConcurrentLogoutTakesOverCleanup(&r)
    await checkFailedLoginCommitRollsBackTransition(&r)
    await checkArgon2idRejected(&r)
    await checkTwoFactorRequired(&r)
    await checkMultiProviderEmailCodeRequest(&r)
    await checkConcurrentTwoFactorSubmissionIsRejected(&r)
    await checkTwoFactorRejectsServerSwitch(&r)
    await checkTwoFactorWithoutPending(&r)
    await checkAccountIDUsesCanonicalFullServerBase(&r)
    await checkColdSessionRestoration(&r)
    await checkStaleSessionMarkerIsCleared(&r)
    await checkLegacyAccountMarkerIsQuarantined(&r)
    await checkLogoutSupersedesSessionRestore(&r)
    await checkBiometricKeyIsAccountBound(&r)
    await checkSessionRestoresAfterSync(&r)
    await checkPasskeyRegistrationImportIsIdempotent(&r)
    await checkPasskeyImportsCoalesceWithPendingCreate(&r)
    await checkPasskeyImportFallsBackWhenTargetDisappears(&r)
    await checkPasskeyImportFallsBackWhenTargetIsSoftDeleted(&r)
    await checkCipherAccessIsAccountScoped(&r)

    // Vault CRUD + lock.
    await checkCreateCipher(&r)
    await checkSoftDeletedCipherIsHidden(&r)
    await checkAllCipherTypesRoundTrip(&r)
    await checkCreateCipherLockedFails(&r)
    await checkLock(&r)

    // Offline outbox paths (create / update / delete enqueue + optimistic local rows).
    await checkCreateCipherOffline(&r)
    await checkOfflineCreateUpdateCoalesces(&r)
    await checkOfflineCreateDeleteCancels(&r)
    await checkMutationWaitsForInFlightCreate(&r)
    await checkDeleteWaitsForInFlightFullSync(&r)
    await checkUpdateCipherOffline(&r)
    await checkPersonalCipherKeyUpdateOffline(&r)
    await checkDeleteCipherOffline(&r)

    // Online update / delete round-trips.
    await checkUpdateCipherOnline(&r)
    await checkPersonalCipherKeyUpdateOnline(&r)
    await checkOrganizationUpdateWithoutKeyIsRejected(&r)
    await checkDeleteCipherOnline(&r)

    // refresh() + logout().
    await checkRefreshSuccess(&r)
    await checkRefreshFailureThrows(&r)
    await checkRefreshNoTokenThrows(&r)
    await checkRefreshTokenIsAccountScoped(&r)
    await checkConcurrentRefreshesAreSerialized(&r)
    await checkLockWaitsForRefreshRotation(&r)
    await checkLogout(&r)

    // DI container resolution via the Has* protocols.
    await checkServiceContainer(&r)

    return r.summary()
}

let failures = await runAllTests()
if failures != 0 { exit(1) }
