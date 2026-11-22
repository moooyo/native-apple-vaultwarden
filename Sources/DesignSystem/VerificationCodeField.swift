import SwiftUI

public struct VerificationCodeField: View {
    @Binding private var code: String
    @FocusState private var focused: Bool
    @ScaledMetric(relativeTo: .title2) private var cellHeight: CGFloat = 52

    public init(code: Binding<String>) { _code = code }

    public var body: some View {
        TextField("6 位验证码", text: $code)
            .textContentType(.oneTimeCode)
            .textFieldStyle(.plain)
            #if os(iOS)
            .keyboardType(.numberPad)
            #endif
            .autocorrectionDisabled()
            .foregroundStyle(.clear)
            .tint(.clear)
            .focused($focused)
            .frame(height: cellHeight)
            .overlay {
                HStack(spacing: 6) {
                    ForEach(0..<6) { index in
                        let digits = Array(code)
                        Text(index < digits.count ? String(digits[index]) : " ")
                            .font(.system(.title2, design: .monospaced).weight(.medium))
                            .frame(maxWidth: .infinity, maxHeight: .infinity)
                            .background(Palette.contentBackground, in: .rect(cornerRadius: CornerRadius.md))
                            .overlay {
                                RoundedRectangle(cornerRadius: CornerRadius.md)
                                    .strokeBorder(focused && index == min(code.count, 5) ? Color.accentColor : Palette.separator,
                                                  lineWidth: focused && index == min(code.count, 5) ? 2 : 0.5)
                            }
                    }
                }
                .allowsHitTesting(false)
                .accessibilityHidden(true)
            }
            .frame(maxWidth: 320)
            .privacySensitive()
            .accessibilityIdentifier("twofactor.code")
            .onAppear { focused = true }
    }
}
