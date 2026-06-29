import Foundation
import Fido2

func runAllTests() -> Int {
    var r = TestRunner()

    checkCBOR(&r)

    return r.summary()
}

let failures = runAllTests()
if failures != 0 { exit(1) }
