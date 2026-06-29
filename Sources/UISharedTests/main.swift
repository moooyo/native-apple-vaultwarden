import Foundation

/// Headless test runner for UIShared (no XCTest on this CLT host). The view models are
/// `@MainActor`, so the whole run executes on the main actor. Fakes back the `AuthService` /
/// `VaultService` seams; TOTP + generator paths use deterministic inputs (a fixed clock, a
/// `MockRandomSource`) for golden-vector checks.
@MainActor
func runAllTests() async -> Int {
    var r = TestRunner()

    // UnlockModel.
    await checkUnlockPasswordSuccess(&r)
    await checkUnlockPasswordError(&r)
    await checkUnlockBiometricsSuccess(&r)
    await checkUnlockBiometricsError(&r)

    // LoginModel.
    await checkLoginSuccess(&r)
    await checkLoginNeedsTwoFactorThenSuccess(&r)
    await checkLoginError(&r)
    await checkLoginUnsupportedKDFMessage(&r)

    // VaultListModel.
    await checkVaultListLoad(&r)
    await checkVaultListSearch(&r)
    await checkVaultListSearchEmptyReloads(&r)
    await checkVaultListRefresh(&r)
    await checkVaultListLoadError(&r)
    await checkVaultListRefreshSyncErrorStillReloads(&r)

    // ItemDetailModel.
    await checkItemDetailRevealAndCopy(&r)
    await checkItemDetailNoLogin(&r)
    await checkItemDetailTOTPGoldenVector(&r)
    await checkItemDetailTOTPInvalidSecret(&r)

    // GeneratorModel.
    await checkGeneratorPasswordDeterministic(&r)
    await checkGeneratorPassphraseGoldenVector(&r)
    await checkGeneratorModeSwitch(&r)
    await checkGeneratorInvalidOptions(&r)
    await checkGeneratorPassphraseNoWordList(&r)

    // SyncStatusModel + SettingsModel.
    await checkSyncStatusSuccess(&r)
    await checkSyncStatusError(&r)
    await checkSettingsDefaultsAndValidation(&r)
    await checkSettingsMutation(&r)

    return r.summary()
}

let failures = await runAllTests()
if failures != 0 { exit(1) }
