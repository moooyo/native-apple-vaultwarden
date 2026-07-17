import Foundation
import SyncEngine

func runAllTests() async -> Int {
    var r = TestRunner()

    // Pure helpers + DTO round-trip (synchronous).
    checkHelpers(&r)
    checkCompleteOutboxCipherPayload(&r)

    // Full sync + incremental revision rule.
    await checkFullSyncUpsert(&r)
    await checkIncrementalRevisionRule(&r)
    await checkFullSyncDeletesMissing(&r)
    await checkServerTrashRowRemovesLiveCipher(&r)
    await checkFullSyncSkipsPendingUpsert(&r)
    await checkFullSyncKeepsPendingOmitted(&r)
    await checkFullSyncScopesPendingOutbox(&r)
    await checkSyncPreservesIdentityAndSSH(&r)

    // Soft-fail (dropped ciphers).
    await checkSoftFailDroppedCiphers(&r)
    await checkWellFormedType7PreservesReadableRow(&r)
    await checkWellFormedType1PreservesReadableRow(&r)

    // AutoFill identity rebuild.
    await checkIdentitiesReplaceAll(&r)
    await checkIdentitiesIncremental(&r)
    await checkIdentitiesDisabledSkips(&r)
    await checkAccountTransitionRevokesStaleIdentityWrite(&r)
    await checkIdentitiesIncludesOTP(&r)
    await checkIdentitiesIncludePasskeys(&r)
    await checkUnfulfillableIdentitiesAreOmitted(&r)
    await checkSoftDeletedRowsAreNotPublished(&r)

    // Outbox flush (create / conflict / update+delete / malformed / delete-404 /
    // transport-leaves-queued / corrupt-token).
    await checkFlushOutboxCreate(&r)
    await checkConcurrentFlushCoalescesCreate(&r)
    await checkLegacyCreateSequenceRemapsServerID(&r)
    await checkLegacyCreateDeleteRemapsServerID(&r)
    await checkPasskeyReceiptFinalizationPreventsReplay(&r)
    await checkFlushOutboxConflict(&r)
    await checkFlushOutboxUpdateAndDelete(&r)
    await checkFlushOutboxMalformedPayload(&r)
    await checkFlushOutboxDelete404Clears(&r)
    await checkFlushOutboxTransportLeavesQueued(&r)
    await checkFlushOutboxCorruptToken(&r)
    await checkFlushOutboxAccountIsolation(&r)

    return r.summary()
}

let failures = await runAllTests()
if failures != 0 { exit(1) }
