import Foundation
@testable import DesignSystem

func checkPasswordStrength(_ r: inout TestRunner) {
    // --- Normalized-score thresholds ---
    r.expect(PasswordStrength.level(forNormalizedScore: 0.0), .veryWeak, "0.0 -> veryWeak")
    r.expect(PasswordStrength.level(forNormalizedScore: 0.19), .veryWeak, "0.19 -> veryWeak")
    r.expect(PasswordStrength.level(forNormalizedScore: 0.20), .weak, "0.20 -> weak (boundary)")
    r.expect(PasswordStrength.level(forNormalizedScore: 0.39), .weak, "0.39 -> weak")
    r.expect(PasswordStrength.level(forNormalizedScore: 0.40), .fair, "0.40 -> fair (boundary)")
    r.expect(PasswordStrength.level(forNormalizedScore: 0.59), .fair, "0.59 -> fair")
    r.expect(PasswordStrength.level(forNormalizedScore: 0.60), .good, "0.60 -> good (boundary)")
    r.expect(PasswordStrength.level(forNormalizedScore: 0.79), .good, "0.79 -> good")
    r.expect(PasswordStrength.level(forNormalizedScore: 0.80), .strong, "0.80 -> strong (boundary)")
    r.expect(PasswordStrength.level(forNormalizedScore: 1.0), .strong, "1.0 -> strong")

    // --- Clamping out-of-range normalized scores ---
    r.expect(PasswordStrength.level(forNormalizedScore: -1.0), .veryWeak, "-1.0 clamps -> veryWeak")
    r.expect(PasswordStrength.level(forNormalizedScore: 2.0), .strong, "2.0 clamps -> strong")

    // --- Raw zxcvbn 0–4 scores ---
    r.expect(PasswordStrength.level(forRawScore: 0), .veryWeak, "raw 0 -> veryWeak")
    r.expect(PasswordStrength.level(forRawScore: 1), .weak, "raw 1 -> weak")
    r.expect(PasswordStrength.level(forRawScore: 2), .fair, "raw 2 -> fair")
    r.expect(PasswordStrength.level(forRawScore: 3), .good, "raw 3 -> good")
    r.expect(PasswordStrength.level(forRawScore: 4), .strong, "raw 4 -> strong")
    r.expect(PasswordStrength.level(forRawScore: 9), .strong, "raw 9 clamps -> strong")
    r.expect(PasswordStrength.level(forRawScore: -3), .veryWeak, "raw -3 clamps -> veryWeak")

    // --- fillFraction is monotonic & in (0, 1] ---
    r.expectClose(PasswordStrength.veryWeak.fillFraction, 0.2, "veryWeak fill 0.2")
    r.expectClose(PasswordStrength.strong.fillFraction, 1.0, "strong fill 1.0")
}
