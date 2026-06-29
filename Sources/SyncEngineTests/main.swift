import Foundation
import SyncEngine

func runAllTests() async -> Int {
    var r = TestRunner()

    // Pure helpers + DTO round-trip (synchronous).
    checkHelpers(&r)

    // Full sync + incremental revision rule.
    await checkFullSyncUpsert(&r)
    await checkIncrementalRevisionRule(&r)
    await checkFullSyncDeletesMissing(&r)
    await checkFullSyncSkipsPendingUpsert(&r)
    await checkFullSyncKeepsPendingOmitted(&r)

    // Soft-fail (dropped ciphers).
    await checkSoftFailDroppedCiphers(&r)

    // AutoFill identity rebuild.
    await checkIdentitiesReplaceAll(&r)
    await checkIdentitiesIncremental(&r)
    await checkIdentitiesDisabledSkips(&r)
    await checkIdentitiesIncludesOTP(&r)

    // Outbox flush (create / conflict / update+delete / malformed / delete-404 /
    // transport-leaves-queued / corrupt-token).
    await checkFlushOutboxCreate(&r)
    await checkFlushOutboxConflict(&r)
    await checkFlushOutboxUpdateAndDelete(&r)
    await checkFlushOutboxMalformedPayload(&r)
    await checkFlushOutboxDelete404Clears(&r)
    await checkFlushOutboxTransportLeavesQueued(&r)
    await checkFlushOutboxCorruptToken(&r)

    return r.summary()
}

let failures = await runAllTests()
if failures != 0 { exit(1) }
