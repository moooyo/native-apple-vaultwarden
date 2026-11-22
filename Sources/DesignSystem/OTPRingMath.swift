import Foundation

public enum OTPRingMath {
    /// Remaining fraction of the current code's lifetime.
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

    public static func formatCode(_ raw: String) -> String {
        guard raw.count >= 6, raw.allSatisfy(\.isNumber) else { return raw }
        var grouped = ""
        for (index, character) in raw.enumerated() {
            if index > 0 && index.isMultiple(of: 3) { grouped.append(" ") }
            grouped.append(character)
        }
        return grouped
    }
}
