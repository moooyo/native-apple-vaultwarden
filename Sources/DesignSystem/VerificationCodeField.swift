import SwiftUI

public struct VerificationCodeField: View {
    @Binding private var code: String
    @FocusState private var focused: Bool
    @Environment(\.dynamicTypeSize) private var typeSize
    @ScaledMetric(relativeTo: .title2) private var cellHeight: CGFloat = 52

    public init(code: Binding<String>) { _code = code }

    public var body: some View {
        let stacked = typeSize.isAccessibilitySize
        TextField("", text: $code)
            .textContentType(.oneTimeCode)
            .textFieldStyle(.plain)
            #if os(iOS)
            .keyboardType(.numberPad)
            #endif
            .autocorrectionDisabled()
            .foregroundStyle(.clear)
            .tint(.clear)
            .focused($focused)
            .frame(height: stacked ? 2 * cellHeight + Spacing.sm : cellHeight)
            .overlay {
                let layout = stacked ? AnyLayout(VStackLayout(spacing: Spacing.sm)) : AnyLayout(HStackLayout(spacing: 18))
                layout {
                    digitGroup(startingAt: 0)
                    digitGroup(startingAt: 3)
                }
                .allowsHitTesting(false)
                .accessibilityHidden(true)
            }
            .frame(maxWidth: 320)
            .privacySensitive()
            .accessibilityLabel("6 位验证码")
            .accessibilityIdentifier("twofactor.code")
            .onAppear { focused = true }
    }

    private func digitGroup(startingAt first: Int) -> some View {
        HStack(spacing: Spacing.sm) {
            ForEach(first..<(first + 3), id: \.self) { index in cell(at: index) }
        }
        .frame(maxWidth: .infinity)
    }

    private func cell(at index: Int) -> some View {
        let digits = Array(code)
        let active = focused && index == min(digits.count, 5)
        return Text(index < digits.count ? String(digits[index]) : " ")
            .font(.system(.title2, design: .monospaced).weight(.medium))
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(Palette.contentBackground, in: .rect(cornerRadius: CornerRadius.md))
            .overlay {
                RoundedRectangle(cornerRadius: CornerRadius.md)
                    .strokeBorder(active ? Color.accentColor : Palette.separator, lineWidth: active ? 2 : 0.5)
            }
    }
}
