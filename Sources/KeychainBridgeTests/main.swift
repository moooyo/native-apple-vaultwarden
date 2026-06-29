import Foundation
import KeychainBridge

func runAllTests() async -> Int {
    var r = TestRunner()
    // Error type is Equatable (used by the harness + callers).
    r.expect(KeychainError.notFound, KeychainError.notFound, "error equatable smoke")
    r.expect(KeychainError.unexpected(-1), KeychainError.unexpected(-1), "unexpected(OSStatus) equatable smoke")
    await checkBiometricUnlock(&r)
    await checkSecrets(&r)
    return r.summary()
}

let failures = await runAllTests()
if failures != 0 { exit(1) }
