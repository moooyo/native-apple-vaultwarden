import SwiftUI

@available(iOS 26.0, macOS 26.0, *)
private struct VaultProminentAction: PrimitiveButtonStyle {
    @Environment(\.colorScheme) private var colorScheme
    @Environment(\.colorSchemeContrast) private var contrast
    let glass: Bool

    func makeBody(configuration: Configuration) -> some View {
        if contrast == .increased {
            // The system accent can lighten behind a white label in Dark Mode.
            // Keep the native filled button, with a contrasting label and symbol.
            let ink: Color = colorScheme == .dark ? .black : .white
            Button(role: configuration.role, action: configuration.trigger) {
                configuration.label.foregroundStyle(ink).tint(ink)
            }
            .buttonStyle(.borderedProminent)
            .tint(Palette.primaryText)
        } else if glass {
            Button(configuration).buttonStyle(.glassProminent)
        } else {
            Button(configuration).buttonStyle(.borderedProminent)
        }
    }
}

@available(iOS 26.0, macOS 26.0, *)
public extension View {
    /// A native primary action with an achromatic fill when Increase Contrast is on.
    func vaultProminentButtonStyle(glass: Bool = false) -> some View {
        buttonStyle(VaultProminentAction(glass: glass))
    }
}
