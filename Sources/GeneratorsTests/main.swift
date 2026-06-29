import Foundation
import Generators

func runAllTests() -> Int {
    var r = TestRunner()

    checkBase32(&r)

    return r.summary()
}

let failures = runAllTests()
if failures != 0 { exit(1) }
