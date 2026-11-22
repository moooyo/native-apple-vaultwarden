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
        GeometryReader { geometry in
            ZStack(alignment: .leading) {
                Rectangle().fill(Palette.controlFill)
                Rectangle()
                    .fill(secondsRemaining <= 5 ? Palette.warning : Palette.accent)
                    .frame(width: geometry.size.width * CGFloat(fraction))
                    .animation(reduceMotion || secondsRemaining >= period ? nil : .linear(duration: 1), value: fraction)
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
    private let action: () -> Void
    private let label: (Bool) -> Content
    @State private var feedbackID: UUID?

    public init(action: @escaping () -> Void, @ViewBuilder label: @escaping (Bool) -> Content) {
        self.action = action
        self.label = label
    }

    public var body: some View {
        Button {
            action()
            feedbackID = UUID()
            AccessibilityNotification.Announcement("已拷贝").post()
        } label: {
            label(feedbackID != nil).contentShape(Rectangle())
        }
        .accessibilityValue("已拷贝", isEnabled: feedbackID != nil)
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

public struct SecretStrengthMeter: View {
    private let strength: PasswordStrength
    private let caption: String?

    public init(strength: PasswordStrength, caption: String? = nil) {
        self.strength = strength
        self.caption = caption
    }

    public var body: some View {
        ViewThatFits(in: .horizontal) {
            HStack(spacing: Spacing.sm) {
                segments.frame(minWidth: 60)
                Text(description).fixedSize()
            }
            VStack(alignment: .leading, spacing: Spacing.xs) {
                segments
                Text(description)
            }
        }
        .font(.footnote.weight(.semibold))
        .foregroundStyle(.secondary)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("密码强度")
        .accessibilityValue(Text(description))
    }

    private var segments: some View {
        HStack(spacing: Spacing.xs) {
            ForEach(0..<4) { index in
                Capsule().fill(index < max(1, strength.rawValue) ? strength.color : Palette.controlFill)
            }
        }
        .frame(height: 4)
    }

    private var description: String {
        let grade: String = switch strength {
        case .veryWeak: "很弱"
        case .weak: "弱"
        case .fair: "中等"
        case .good: "强"
        case .strong: "极强"
        }
        return caption.map { "\(grade) · \($0)" } ?? grade
    }
}
