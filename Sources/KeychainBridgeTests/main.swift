import Foundation
import KeychainBridge

func runAllTests() async -> Int {
    var r = TestRunner()
    // Error type is Equatable (used by the harness + callers).
    r.expect(KeychainError.notFound, KeychainError.notFound, "error equatable smoke")
    r.expect(KeychainError.unexpected(-1), KeychainError.unexpected(-1), "unexpected(OSStatus) equatable smoke")
    await checkBiometricUnlock(&r)
    #if os(macOS)
    await checkLocalBiometricEnvelope(&r)
    #endif
    await checkSecrets(&r)
    await checkPasskeyHandoff(&r)
    await checkPasskeyHandoffRejectsTampering(&r)
    await checkPasskeyHandoffRollsBackSecret(&r)
    await checkPasskeyHandoffRejectsSessionSwitch(&r)
    await checkPasskeyHandoffKeepsCommittedRegistrationAfterSessionSwitch(&r)
    await checkPasskeyHandoffAcknowledgementReadback(&r)
    await checkPasskeyHandoffLegacyMigration(&r)
    await checkPasskeyHandoffFilesystemHardening(&r)
    return r.summary()
}

let failures = await runAllTests()
if failures != 0 { exit(1) }
