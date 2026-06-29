import Foundation

// Pure-logic test entrypoint for DesignSystem (SwiftUI Views are verified by
// `swift build`; only the testable decision functions are exercised here).
func runAllTests() -> Int {
    var r = TestRunner()

    checkGlassResolution(&r)
    checkOTPRingMath(&r)
    checkPasswordStrength(&r)

    return r.summary()
}

let failures = runAllTests()
if failures != 0 { exit(1) }
