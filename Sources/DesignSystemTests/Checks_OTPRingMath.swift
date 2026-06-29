import Foundation
@testable import DesignSystem

func checkOTPRingMath(_ r: inout TestRunner) {
    // Spec cases from the task brief.
    r.expectClose(OTPRingMath.progress(secondsRemaining: 30, period: 30), 1.0, "30/30 -> 1.0")
    r.expectClose(OTPRingMath.progress(secondsRemaining: 15, period: 30), 0.5, "15/30 -> 0.5")
    r.expectClose(OTPRingMath.progress(secondsRemaining: 0, period: 30), 0.0, "0/30 -> 0.0")

    // Clamping: > period clamps to 1.0; negative clamps to 0.0.
    r.expectClose(OTPRingMath.progress(secondsRemaining: 45, period: 30), 1.0, "45/30 clamps to 1.0")
    r.expectClose(OTPRingMath.progress(secondsRemaining: -5, period: 30), 0.0, "-5/30 clamps to 0.0")

    // Non-positive period -> 0 (no divide-by-zero).
    r.expectClose(OTPRingMath.progress(secondsRemaining: 10, period: 0), 0.0, "period 0 -> 0.0")
    r.expectClose(OTPRingMath.progress(secondsRemaining: 10, period: -1), 0.0, "period -1 -> 0.0")

    // A different period (Steam / 60s tokens).
    r.expectClose(OTPRingMath.progress(secondsRemaining: 30, period: 60), 0.5, "30/60 -> 0.5")

    // --- formatCode: 6-digit numeric grouped; everything else unchanged ---
    r.expect(OTPRingMath.formatCode("123456"), "123 456", "6-digit grouped")
    r.expect(OTPRingMath.formatCode("000000"), "000 000", "leading-zero grouped")
    r.expect(OTPRingMath.formatCode("12345"), "12345", "5-digit unchanged")
    r.expect(OTPRingMath.formatCode("12345678"), "12345678", "8-digit unchanged")
    r.expect(OTPRingMath.formatCode("2K9F4"), "2K9F4", "Steam alphabetic unchanged")
}
