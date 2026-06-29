import Foundation

// MARK: - OTP ring progress math (pure logic, testable)
//
// The countdown ring fraction is derived from `secondsRemaining / period`. Factored
// out of `OTPRingView` so the boundary behaviour (full at the start of a window, zero
// at the end, clamping for bad inputs) is unit-tested headlessly.

public enum OTPRingMath {
    /// Progress fraction in [0, 1] for the countdown ring.
    ///
    /// `1.0` means a full window remains (just refreshed), `0.0` means the window is
    /// about to roll over. The result is clamped to [0, 1] and a non-positive
    /// `period` yields `0` rather than dividing by zero.
    ///
    /// - Parameters:
    ///   - secondsRemaining: seconds left in the current TOTP window.
    ///   - period: the TOTP period in seconds (typically 30).
    public static func progress(secondsRemaining: Int, period: Int) -> Double {
        guard period > 0 else { return 0 }
        let clampedRemaining = min(max(secondsRemaining, 0), period)
        return Double(clampedRemaining) / Double(period)
    }

    /// Group a numeric 6-digit OTP into two halves ("123456" → "123 456") for
    /// readability. Non-6-digit and Steam (alphabetic) codes are returned unchanged.
    public static func formatCode(_ raw: String) -> String {
        guard raw.count == 6, raw.allSatisfy(\.isNumber) else { return raw }
        let mid = raw.index(raw.startIndex, offsetBy: 3)
        return "\(raw[raw.startIndex..<mid]) \(raw[mid...])"
    }
}
