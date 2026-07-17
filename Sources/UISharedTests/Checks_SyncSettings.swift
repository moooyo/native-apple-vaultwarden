import Foundation
import SyncEngine
import VaultRepository
import AppShared
import UIShared

@MainActor
func checkSyncStatusSuccess(_ r: inout TestRunner) async {
    let outcome = SyncOutcome(upserted: 5, deletedLocally: 1, dropped: 0,
                              droppedMessages: [], identitiesWritten: 5)
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

@MainActor
func checkSettingsDefaultsAndValidation(_ r: inout TestRunner) async {
    let model = SettingsModel()
    r.expect(model.autoLockTimeout, .fiveMinutes, "Settings: default auto-lock five minutes")
    r.expectFalse(model.biometricUnlockEnabled, "Settings: biometrics off by default")
    r.expect(model.availableTimeouts.count, AutoLockTimeout.allCases.count, "Settings: lists all timeouts")

    // Empty default server URL is invalid.
    r.expectFalse(model.isServerURLValid, "Settings: empty server URL invalid")

    model.serverURL = "https://vault.example.com"
    r.expectTrue(model.isServerURLValid, "Settings: https URL valid")

    model.serverURL = "not a url"
    r.expectFalse(model.isServerURLValid, "Settings: bare string invalid")

    model.serverURL = "ftp://example.com"
    r.expectFalse(model.isServerURLValid, "Settings: non-http scheme invalid")

    model.serverURL = "https://user:secret@example.com"
    r.expectFalse(model.isServerURLValid, "Settings: URL credentials invalid")

    model.serverURL = "https://example.com?tenant=one"
    r.expectFalse(model.isServerURLValid, "Settings: query-bearing base URL invalid")
}

@MainActor
func checkSettingsMutation(_ r: inout TestRunner) async {
    let model = SettingsModel(serverURL: "https://a.com", autoLockTimeout: .never,
                              biometricUnlockEnabled: true)
    r.expect(model.autoLockTimeout, .never, "Settings: init applies timeout")
    r.expectTrue(model.biometricUnlockEnabled, "Settings: init applies biometric flag")

    model.autoLockTimeout = .immediately
    model.biometricUnlockEnabled = false
    r.expect(model.autoLockTimeout, .immediately, "Settings: timeout mutable")
    r.expectFalse(model.biometricUnlockEnabled, "Settings: biometric flag mutable")
}
