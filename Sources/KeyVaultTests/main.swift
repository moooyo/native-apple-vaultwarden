import Foundation
import KeyVault

func runAllTests() async -> Int {
    var r = TestRunner()
    r.expect(KeyVaultError.locked, KeyVaultError.locked, "error equatable smoke")
    await checkUnlock(&r)
    await checkDecrypt(&r)
    await checkLock(&r)
    return r.summary()
}

let failures = await runAllTests()
if failures != 0 { exit(1) }
