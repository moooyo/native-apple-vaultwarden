import SwiftUI

// MARK: - Password-strength color thresholds (pure logic, testable)
//
// A small helper that maps a normalized strength score to a semantic strength level
// (and from there a color + label). The threshold math is factored into pure
// functions so it can be unit-tested headlessly; the `Color`/`Text` mapping is a thin
// view-layer convenience on top.

/// Discrete strength levels matching the zxcvbn 0–4 convention Bitwarden uses.
public enum PasswordStrength: Int, Equatable, Sendable, CaseIterable {
    case veryWeak = 0
    case weak = 1
    case fair = 2
    case good = 3
    case strong = 4

    /// Map a normalized score in [0, 1] to a discrete level.
    ///
    /// Thresholds (inclusive lower bound):
    ///   [0.00, 0.20) → veryWeak
    ///   [0.20, 0.40) → weak
    ///   [0.40, 0.60) → fair
    ///   [0.60, 0.80) → good
    ///   [0.80, 1.00] → strong
    /// The input is clamped to [0, 1] so out-of-range scores never trap.
    public static func level(forNormalizedScore score: Double) -> PasswordStrength {
        let s = min(max(score, 0), 1)
        switch s {
        case ..<0.20: return .veryWeak
        case ..<0.40: return .weak
        case ..<0.60: return .fair
        case ..<0.80: return .good
        default: return .strong
        }
    }

    /// Map a raw zxcvbn-style score (0–4) directly. Out-of-range values clamp.
    public static func level(forRawScore raw: Int) -> PasswordStrength {
        PasswordStrength(rawValue: min(max(raw, 0), 4)) ?? .veryWeak
    }

    /// A short human label.
    public var label: String {
        switch self {
        case .veryWeak: return "Very Weak"
        case .weak: return "Weak"
        case .fair: return "Fair"
        case .good: return "Good"
        case .strong: return "Strong"
        }
    }

    /// Fraction of a meter to fill, in [0, 1].
    public var fillFraction: Double {
        Double(rawValue + 1) / Double(PasswordStrength.allCases.count)
    }
}

public extension PasswordStrength {
    /// Semantic color for the level. Kept here (not in pure logic) because `Color`
    /// is a view type, but the *level* selection above is pure and tested.
    var color: Color {
        switch self {
        case .veryWeak: return Palette.danger
        case .weak: return Palette.warning
        case .fair: return Palette.caution
        case .good: return Palette.success
        case .strong: return Palette.success
        }
    }
}
