import Foundation
import Fido2

func runAllTests() -> Int {
    var r = TestRunner()

    checkCBOR(&r)
    checkCredentialKey(&r)
    checkCOSEKey(&r)
    checkAuthData(&r)
    checkAssertion(&r)
    checkRegistration(&r)

    return r.summary()
}

let failures = runAllTests()
if failures != 0 { exit(1) }
