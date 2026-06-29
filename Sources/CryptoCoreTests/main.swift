import Foundation
import CryptoCore

func runAllTests() -> Int {
    var r = TestRunner()

    // Smoke
    r.expect(CryptoCore.version, "0.1.0", "module loads")

    // Later tasks add their registrations here, e.g.:
    // checkEncryptionType(&r)
    // checkEncString(&r)
    // ...

    return r.summary()
}

let failures = runAllTests()
if failures != 0 { exit(1) }
