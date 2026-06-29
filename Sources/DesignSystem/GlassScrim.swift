import SwiftUI

// MARK: - GlassScrim
//
// A scrim that sits *behind* sensitive content (a revealed secret, a card number) to
// guarantee legibility and resist shoulder-surfing. Liquid Glass intent:
//
//   * Default: a `.regular` Liquid Glass material — frosted enough that whatever is
//     behind it is obscured, while still feeling like part of the OS material system.
//   * Accessibility fallback: when Reduce Transparency is on OR the color scheme
//     contrast is increased, we drop the live material entirely and render a SOLID
//     opaque background (no blur, maximum contrast). This is the
//     `resolveSensitiveGlass(...)` decision, which provably never selects clear glass.
//
// Use via the `.glassScrim(cornerRadius:)` modifier as a background for sensitive UI.

@available(iOS 26.0, macOS 26.0, *)
public struct GlassScrim: ViewModifier {
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
    @Environment(\.colorSchemeContrast) private var contrast

    private let cornerRadius: CGFloat

    public init(cornerRadius: CGFloat = CornerRadius.md) {
        self.cornerRadius = cornerRadius
    }

    private var resolved: ResolvedGlass {
        resolveSensitiveGlass(
            reduceTransparency: reduceTransparency,
            increaseContrast: contrast == .increased
        )
    }

    public func body(content: Content) -> some View {
        let shape = RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
        return content.background {
            switch resolved {
            case .regular, .clear:
                // `.clear` is never returned for a sensitive scrim, but handle it by
                // using the regular material to stay safe.
                Color.clear.glassEffect(.regular, in: shape)
            case .identity:
                // Opaque fallback: a solid content-background fill, no blur.
                shape.fill(Palette.contentBackground)
            }
        }
    }
}

@available(iOS 26.0, macOS 26.0, *)
public extension View {
    /// Render an accessible scrim behind sensitive content. Falls back to a solid
    /// opaque background under Reduce Transparency / Increased Contrast.
    func glassScrim(cornerRadius: CGFloat = CornerRadius.md) -> some View {
        modifier(GlassScrim(cornerRadius: cornerRadius))
    }
}
