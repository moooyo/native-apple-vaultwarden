import Foundation
import Networking
import SyncEngine
import VaultRepository
import AppShared
import UIShared

@MainActor
func checkSyncStatusSuccess(_ r: inout TestRunner) async {
    let outcome = SyncOutcome(upserted: 5, deletedLocally: 1, dropped: 0,
                              droppedMessages: [], identitiesWritten: 5,
                              profile: .init(email: "demo@example.com", name: " Demo ", serverURL: "https://vault.example.com/"))
    let vault = FakeVaultService(syncOutcome: outcome)
    let fixed = Date(timeIntervalSince1970: 1_700_000_000)
    let model = SyncStatusModel(vault: vault, now: { fixed })

    r.expectNil(model.lastSync, "Sync: no lastSync before first sync")
    let ok = await model.sync()

    r.expectTrue(ok, "Sync: returns true on success")
    r.expectFalse(model.isSyncing, "Sync: isSyncing reset after sync")
    r.expect(model.lastSync, fixed, "Sync: lastSync set to clock time")
    r.expect(model.lastOutcome, outcome, "Sync: lastOutcome captured")
    r.expectNil(model.errorMessage, "Sync: no error on success")
    r.expect(model.accountDisplayName(email: "DEMO@example.com", serverURL: "https://vault.example.com"), "Demo",
             "Settings: display name belongs to the active deployment and email")
    r.expectNil(model.accountDisplayName(email: "demo@example.com", serverURL: "https://vault.example.com/other"),
                "Settings: a different deployment cannot reuse the profile name")
    r.expectNil(model.accountDisplayName(email: "someone@example.com", serverURL: "https://vault.example.com"),
                "Settings: a different account cannot reuse the profile name")
}

@MainActor
func checkSyncStatusError(_ r: inout TestRunner) async {
    let vault = FakeVaultService()
    await vault.setSyncError(RepositoryError.underlying(kind: .sync, description: "down"))
    let model = SyncStatusModel(vault: vault)

    let ok = await model.sync()

    r.expectFalse(ok, "Sync: returns false on error")
    r.expectNotNil(model.errorMessage, "Sync: errorMessage set on failure")
    r.expectNil(model.lastSync, "Sync: lastSync unchanged on failure")
    r.expectFalse(model.isSyncing, "Sync: isSyncing reset after failure")
}

private actor ControlledSyncSession {
    var current: AccountSessionLease?
    init(_ current: AccountSessionLease) { self.current = current }
    func select(_ value: AccountSessionLease?) { current = value }
}

private actor PausedSyncOutcome {
    private var waiting: CheckedContinuation<Void, Never>?
    private var started: CheckedContinuation<Void, Never>?

    func pause() async {
        await withCheckedContinuation { continuation in
            waiting = continuation
            started?.resume()
            started = nil
        }
    }

    func waitUntilStarted() async {
        if waiting == nil { await withCheckedContinuation { started = $0 } }
    }

    func finish() { waiting?.resume(); waiting = nil }
}

@MainActor
func checkSendSyncAccess(_ runner: inout TestRunner) async {
    let first = AccountSessionLease(accountID: "first", generation: 1)
    let second = AccountSessionLease(accountID: "second", generation: 2)
    let session = ControlledSyncSession(first)
    let access = VaultSyncAccess { await session.current }
    let outcome = SyncOutcome(upserted: 0, deletedLocally: 0, dropped: 0, droppedMessages: [], identitiesWritten: 0, sendCount: 3)
    let vault = FakeVaultService(syncOutcome: outcome)
    let manual = SyncStatusModel(vault: vault, syncAccess: access)
    _ = await access.session()
    var windows = [0, 0]
    let observer = access.observe(first) { windows[0] += 1 }
    let otherWindow = access.observe(first) { windows[1] += 1 }
    var dataChanges = 0
    func lifecycle(imported: Bool = false) async -> Bool {
        await VaultLifecycleSync.run(access: access, drain: { imported }, synchronize: { _ in try await vault.sync() }, dataChanged: { dataChanges += 1 })
    }
    runner.expectTrue(await manual.sync(), "manual sync obtains the authorized Send count")
    runner.expect(access.sendCount, 3, "authorized count is shared with other windows")
    await vault.setSyncError(NetworkingError.serverUnreachable)
    runner.expectFalse(await lifecycle(), "ordinary offline refresh fails without reporting success")
    runner.expect(windows, [0, 0], "offline refresh leaves visible records alone")
    runner.expectFalse(access.sendListingDenied, "ordinary offline status is not authorization loss")
    runner.expect(dataChanges, 0, "an offline refresh without imports does not trigger an extra data read")
    runner.expect(access.successfulSyncs, 1, "offline sync does not release a pending Send refresh")

    let beforeDenial = access.sendRevision
    await vault.setSyncError(NetworkingError.http(status: 403, body: "Forbidden"))
    runner.expectFalse(await lifecycle(), "foreground 403 is a failure")
    runner.expect(windows, [1, 1], "both windows clear before lifecycle sync returns")
    runner.expect(dataChanges, 0, "revocation does not depend on a data revision or another list request")
    runner.expectTrue(access.sendListingDenied, "both windows share explicit denial")
    runner.expect(access.successfulSyncs, 1, "an explicit denial does not trigger a redundant read")
    access.recordSendCount(14, for: first, revision: beforeDenial)
    runner.expectNil(access.sendCount, "a stale notification cannot resurrect the badge")
    await vault.setSyncError(RepositoryError.vaultAccessDenied)
    runner.expectFalse(await manual.sync(), "manual repository denial takes the same revocation path")
    runner.expect(windows, [2, 2], "manual sync also invalidates independent windows")
    runner.expectFalse(await lifecycle(imported: true), "denied sync with an unrelated import still fails")
    runner.expect(dataChanges, 1, "a real import keeps its independent data notification")
    let partial = SyncOutcome(upserted: 1, deletedLocally: 0, dropped: 1, droppedMessages: [], identitiesWritten: 0)
    let partialVault = FakeVaultService(syncOutcome: partial)
    runner.expectTrue(await VaultLifecycleSync.run(access: access, drain: { false }, synchronize: { _ in try await partialVault.sync() },
                                                  dataChanged: { dataChanges += 1 }), "a usable vault response need not carry a Send count")
    runner.expectTrue(access.sendListingDenied, "partial sync cannot reauthorize plaintext or its count")
    runner.expectNil(access.sendCount, "only an authoritative listing can restore a count")
    runner.expect(access.successfulSyncs, 2, "a new successful sync permits an independent authorized Send list read")
    await vault.setSyncError(nil)
    runner.expectTrue(await lifecycle(), "a later complete synchronization can restore the account")
    runner.expect(access.sendCount, 3, "fresh complete outcome restores the badge")
    runner.expectFalse(access.sendListingDenied, "fresh full data can be read normally")

    let pause = PausedSyncOutcome()
    let delayed = Task { @MainActor in
        try? await access.perform { _ in await pause.pause(); throw NetworkingError.unauthorized }
    }
    await pause.waitUntilStarted()
    await session.select(second)
    _ = await access.session()
    var replacementDenials = 0
    let replacement = access.observe(second) { replacementDenials += 1 }
    access.recordSendCount(2, for: second, revision: access.sendRevision)
    await pause.finish()
    _ = await delayed.value
    runner.expect(replacementDenials, 0, "a delayed denial cannot clear the replacement session")
    runner.expect(access.sendCount, 2, "a delayed denial cannot erase a different account's count")
    await session.select(nil)
    _ = await access.session()
    runner.expect(replacementDenials, 1, "observing a locked session invalidates the prior workspace")
    access.removeObserver(observer)
    access.removeObserver(otherWindow)
    access.removeObserver(replacement)
}

@MainActor
func checkSettingsDefaultsAndValidation(_ r: inout TestRunner) async {
    let model = SettingsModel()
    r.expect(model.autoLockTimeout, .fiveMinutes, "Settings: default auto-lock five minutes")
    r.expectFalse(model.biometricUnlockEnabled, "Settings: biometrics off by default")
    r.expect(model.availableTimeouts, [.immediately, .oneMinute, .fiveMinutes, .fifteenMinutes, .oneHour],
             "Settings: only timed policies are offered on mobile")

    // Empty default server URL is invalid.
    r.expectFalse(model.isServerURLValid, "Settings: empty server URL invalid")

    model.serverURL = "https://vault.example.com"
    r.expectTrue(model.isServerURLValid, "Settings: https URL valid")
    r.expect(model.serverHost, "vault.example.com", "Settings: account card displays the configured host")

    model.serverURL = "not a url"
    r.expectFalse(model.isServerURLValid, "Settings: bare string invalid")

    model.serverURL = "ftp://example.com"
    r.expectFalse(model.isServerURLValid, "Settings: non-http scheme invalid")

    model.serverURL = "https://user:secret@example.com"
    r.expectFalse(model.isServerURLValid, "Settings: URL credentials invalid")
    r.expectNil(model.serverHost, "Settings: no server label for a URL containing credentials")

    model.serverURL = "https://example.com?tenant=one"
    r.expectFalse(model.isServerURLValid, "Settings: query-bearing base URL invalid")
}

@MainActor
func checkSettingsMutation(_ r: inout TestRunner) async {
    let model = SettingsModel(serverURL: "https://a.com", autoLockTimeout: .onSleep,
                              biometricUnlockEnabled: true)
    r.expect(model.autoLockTimeout, .onSleep, "Settings: init applies timeout")
    r.expectTrue(model.biometricUnlockEnabled, "Settings: init applies biometric flag")

    model.autoLockTimeout = .immediately
    model.biometricUnlockEnabled = false
    r.expect(model.autoLockTimeout, .immediately, "Settings: timeout mutable")
    r.expectFalse(model.biometricUnlockEnabled, "Settings: biometric flag mutable")
}
