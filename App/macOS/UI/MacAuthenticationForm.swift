import DesignSystem
import SwiftUI

struct MacAuthenticationForm<Fields: View, Footer: View>: View {
    let disablesFields: Bool
    @ViewBuilder let fields: () -> Fields
    @ViewBuilder let footer: () -> Footer

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(spacing: Spacing.lg, content: fields)
                    .frame(maxWidth: 340)
                    .frame(maxWidth: .infinity)
                    .padding(Spacing.lg)
                    .disabled(disablesFields)
            }
            .defaultScrollAnchor(.center, for: .alignment)
            HStack(content: footer)
                .padding(Spacing.md)
        }
        .background(Palette.groupedBackground)
    }
}

struct MacMasterPasswordRow: View {
    @Binding var text: String
    @Binding var isRevealed: Bool
    @Binding var isFocused: Bool
    let accessibilityIdentifier: String
    let onSubmit: () -> Void
    @Environment(\.locale) private var locale

    var body: some View {
        ZStack(alignment: .trailing) {
            MacMasterPasswordField(text: $text, prompt: MacLocalization.text("Master password", locale: locale),
                                   isRevealed: isRevealed, isFocused: $isFocused,
                                   accessibilityIdentifier: accessibilityIdentifier, onSubmit: onSubmit)
                .privacySensitive()
                .padding(.leading, 12).padding(.trailing, 36)
            Button(isRevealed ? "Hide master password" : "Show master password", systemImage: isRevealed ? "eye.slash" : "eye") {
                isRevealed.toggle()
                isFocused = true
            }
            .labelStyle(.iconOnly).buttonStyle(.borderless)
            .controlSize(.small).padding(.trailing, 10)
            .accessibilityIdentifier("\(accessibilityIdentifier).visibility")
        }
        .modifier(MacAuthenticationFieldBorder(focused: isFocused))
    }
}

struct MacAuthenticationFieldBorder: ViewModifier {
    let focused: Bool

    func body(content: Content) -> some View {
        let shape = RoundedRectangle(cornerRadius: 12, style: .continuous)
        content
            .font(.system(size: 15))
            .frame(minHeight: 40)
            .background(Palette.contentBackground, in: shape)
            .overlay { shape.strokeBorder(focused ? Color.accentColor : Palette.separator, lineWidth: focused ? 3 : 0.5).allowsHitTesting(false) }
    }
}
