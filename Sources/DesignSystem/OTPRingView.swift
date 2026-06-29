import SwiftUI
import Generators

// MARK: - OTPRingView
//
// A circular countdown ring around the formatted TOTP code. The ring fraction is the
// pure `OTPRingMath.progress(secondsRemaining:period:)` value, so the visual is just a
// trimmed `Circle` stroke. Liquid Glass intent: the code itself is sensitive, so it is
// rendered on an opaque content layer (monospaced, high contrast) — never on clear
// glass. The ring is decorative chrome.
//
// The view is intentionally "dumb": it takes a code string + seconds + period and
// does no timekeeping. The owning view model ticks a timer and feeds fresh values.

@available(iOS 26.0, macOS 26.0, *)
public struct OTPRingView: View {
    private let code: String
    private let secondsRemaining: Int
    private let period: Int
    private let ringSize: CGFloat

    /// - Parameters:
    ///   - code: the already-formatted TOTP code to display (e.g. "123 456").
    ///   - secondsRemaining: seconds left in the current window.
    ///   - period: the TOTP period (seconds).
    ///   - ringSize: diameter of the countdown ring.
    public init(code: String, secondsRemaining: Int, period: Int, ringSize: CGFloat = 44) {
        self.code = code
        self.secondsRemaining = secondsRemaining
        self.period = period
        self.ringSize = ringSize
    }

    /// Convenience initializer that formats the code from a `TOTPConfiguration` at the
    /// given instant. The configuration's `period` drives both the code and the ring.
    public init(configuration: TOTPConfiguration, at date: Date = Date(), ringSize: CGFloat = 44) {
        let raw = TOTP.code(for: configuration, at: date)
        self.code = OTPRingMath.formatCode(raw)
        self.secondsRemaining = TOTP.secondsRemaining(for: configuration, at: date)
        self.period = configuration.period
        self.ringSize = ringSize
    }

    private var progress: Double {
        OTPRingMath.progress(secondsRemaining: secondsRemaining, period: period)
    }

    /// Color shifts to a warning tint as the window runs out, aiding low-vision users
    /// who can't read the thin ring.
    private var ringColor: Color {
        progress <= 0.2 ? Palette.warning : Palette.accent
    }

    public var body: some View {
        HStack(spacing: Spacing.md) {
            Text(code)
                .font(Typography.code)
                .monospacedDigit()
                .foregroundStyle(Palette.primaryText)
                .accessibilityLabel("One-time code")
                .accessibilityValue(code.replacingOccurrences(of: " ", with: ""))

            ZStack {
                Circle()
                    .stroke(Palette.separator, lineWidth: 3)
                Circle()
                    .trim(from: 0, to: progress)
                    .stroke(ringColor, style: StrokeStyle(lineWidth: 3, lineCap: .round))
                    .rotationEffect(.degrees(-90)) // start the sweep at 12 o'clock
                    .animation(.linear(duration: 0.25), value: progress)
                Text("\(secondsRemaining)")
                    .font(.caption2.weight(.semibold))
                    .monospacedDigit()
                    .foregroundStyle(Palette.secondaryText)
            }
            .frame(width: ringSize, height: ringSize)
            .accessibilityLabel("Seconds remaining")
            .accessibilityValue("\(secondsRemaining)")
        }
    }
}
