import Accessibility
import SwiftUI

public struct OTPCountdownBar: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    private let secondsRemaining: Int
    private let period: Int

    public init(secondsRemaining: Int, period: Int) {
        self.secondsRemaining = secondsRemaining
        self.period = period
    }

    public var body: some View {
        let fraction = OTPRingMath.progress(secondsRemaining: secondsRemaining, period: period)
        ZStack {
            Rectangle().fill(Palette.controlFill)
            Rectangle()
                .fill(secondsRemaining <= 5 ? Palette.warning : Palette.accent)
                .transaction { $0.animation = nil }
                .animation(reduceMotion || secondsRemaining >= period ? nil : .linear(duration: 1)) { bar in
                    bar.scaleEffect(x: CGFloat(fraction), y: 1, anchor: .leading)
                }
        }
        .frame(height: LayoutMetric.countdownHeight)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("验证码剩余时间")
        .accessibilityValue(Text("\(max(0, secondsRemaining)) 秒"))
    }
}

public struct ColoredSecretText: View {
    public enum Usage {
        case field, generated
    }

    private let value: String
    private let usage: Usage

    public init(_ value: String, usage: Usage = .field) {
        self.value = value
        self.usage = usage
    }

    public var body: some View {
        Text(styledValue)
            .privacySensitive()
    }

    private var styledValue: AttributedString {
        var result = AttributedString()
        for character in value {
            var run = AttributedString(String(character))
            if character.isNumber {
                run.foregroundColor = usage == .generated ? .indigo : .blue
            } else if !character.isLetter && !character.isWhitespace {
                run.foregroundColor = usage == .generated ? .pink : .orange
            } else {
                run.foregroundColor = .primary
            }
            result.append(run)
        }
        return result
    }
}

public struct InlineCopyButton<Content: View>: View {
    private let copy: () -> Bool
    private let label: (Bool) -> Content
    @State private var feedbackID: UUID?
    #if os(macOS)
    @Environment(\.locale) private var locale
    #endif

    public init(action: @escaping () -> Void, @ViewBuilder label: @escaping (Bool) -> Content) {
        self.init(copy: { action(); return true }, label: label)
    }

    public init(copy: @escaping () -> Bool, @ViewBuilder label: @escaping (Bool) -> Content) {
        self.copy = copy
        self.label = label
    }

    private var feedback: String {
        #if os(macOS)
        Bundle.main.localizedString(forKey: "Copied", value: "Copied", table: nil, localizations: [locale.language])
        #else
        "已拷贝"
        #endif
    }

    private var accessibilityFeedback: Text {
        #if os(macOS)
        Text(verbatim: feedback)
        #else
        Text("已拷贝")
        #endif
    }

    public var body: some View {
        Button {
            guard copy() else { feedbackID = nil; return }
            feedbackID = UUID()
            AccessibilityNotification.Announcement(feedback).post()
        } label: {
            label(feedbackID != nil).contentShape(Rectangle())
        }
        .accessibilityValue(accessibilityFeedback, isEnabled: feedbackID != nil)
        .task(id: feedbackID) { @MainActor in
            guard let current = feedbackID else { return }
            do {
                try await Task.sleep(for: .milliseconds(1600))
            } catch {
                return
            }
            if feedbackID == current { feedbackID = nil }
        }
    }
}

public struct InlineCopyIndicator: View {
    public init() {}

    public var body: some View {
        HStack(spacing: Spacing.xs) {
            Image(systemName: "checkmark").foregroundStyle(Palette.success)
            Text("已拷贝").foregroundStyle(.primary)
        }
        .font(.subheadline.weight(.medium))
        .accessibilityHidden(true)
    }
}

public struct OTPRowStatus: View {
    private let seconds: Int
    private let copied: Bool
    private let showsSecondsNormally: Bool
    private let font: Font
    private let alignment: HorizontalAlignment

    public init(seconds: Int, copied: Bool, showsSecondsNormally: Bool = false, font: Font = .footnote,
                alignment: HorizontalAlignment = .leading) {
        self.seconds = seconds
        self.copied = copied
        self.showsSecondsNormally = showsSecondsNormally
        self.font = font
        self.alignment = alignment
    }

    public var body: some View {
        Group {
            if copied && seconds <= 5 {
                ViewThatFits(in: .horizontal) {
                    HStack(spacing: Spacing.sm) { InlineCopyIndicator(); countdown }.fixedSize()
                    VStack(alignment: alignment, spacing: Spacing.xxs) { InlineCopyIndicator(); countdown }
                }
            } else if copied {
                InlineCopyIndicator()
            } else if seconds <= 5 || showsSecondsNormally {
                countdown
            }
        }
        .accessibilityHidden(true)
    }

    private var countdown: some View {
        Text("\(seconds) 秒").font(font.monospacedDigit()).foregroundStyle(.secondary)
    }
}

public struct SecretStrengthMeter: View {
    private let strength: PasswordStrength
    private let caption: Text?

    public init(strength: PasswordStrength, caption: String? = nil) {
        self.strength = strength
        self.caption = caption.map { Text($0) }
    }

    public init(strength: PasswordStrength, localizedCaption: Text) {
        self.strength = strength
        caption = localizedCaption
    }

    public var body: some View {
        ViewThatFits(in: .horizontal) {
            HStack(spacing: Spacing.sm) {
                segments.frame(minWidth: 60)
                description.fixedSize()
            }
            VStack(alignment: .leading, spacing: Spacing.xs) {
                segments
                description
            }
        }
        .font(.footnote.weight(.semibold))
        .foregroundStyle(.secondary)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("密码强度")
        .accessibilityValue(description)
    }

    private var segments: some View {
        HStack(spacing: Spacing.xs) {
            ForEach(0..<4) { index in
                Capsule().fill(index < max(1, strength.rawValue) ? strength.color : Palette.controlFill)
            }
        }
        .frame(height: 4)
    }

    private var description: Text {
        let grade: LocalizedStringKey = switch strength {
        case .veryWeak: "很弱"
        case .weak: "弱"
        case .fair: "中等"
        case .good: "强"
        case .strong: "极强"
        }
        return caption.map { Text("\(Text(grade)) · \($0)") } ?? Text(grade)
    }
}
