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

    // Soft-fail (dropped ciphers).
    await checkSoftFailDroppedCiphers(&r)

    // AutoFill identity rebuild.
    await checkIdentitiesReplaceAll(&r)
    await checkIdentitiesIncremental(&r)
    await checkIdentitiesDisabledSkips(&r)
    await checkIdentitiesIncludesOTP(&r)

    // Outbox flush (create / conflict / update+delete / malformed).
    await checkFlushOutboxCreate(&r)
    await checkFlushOutboxConflict(&r)
    await checkFlushOutboxUpdateAndDelete(&r)
    await checkFlushOutboxMalformedPayload(&r)

    return r.summary()
}

let failures = await runAllTests()
if failures != 0 { exit(1) }
