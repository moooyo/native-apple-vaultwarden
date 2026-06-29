import Foundation
import VaultModels
import CryptoCore

func runAllTests() -> Int {
    var r = TestRunner()

    checkCasing(&r)
    checkEnums(&r)
    checkAuth(&r)
    checkCipher(&r)
    checkSync(&r)

    return r.summary()
}

let failures = runAllTests()
if failures != 0 { exit(1) }
