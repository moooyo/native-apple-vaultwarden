import SwiftUI

// MARK: - Glass helpers
//
// A view-facing convenience over the pure `resolveGlass(...)` decision. Use
// `.glassStyle(in:)` on a *decorative* custom surface (a pill, a floating accessory)
// to apply `.glassEffect(.regular)` that automatically drops to `.identity` (no glass)
// under Reduce Transparency or Increased Contrast.
//
// Do NOT use this for sensitive content — use `GlassScrim` / `SecureRevealView` which
// additionally guarantee a solid opaque scrim and never clear glass.

@available(iOS 26.0, macOS 26.0, *)
public struct DecorativeGlassModifier<S: Shape>: ViewModifier {
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
    @Environment(\.colorSchemeContrast) private var contrast

    private let shape: S
    private let tint: Color?

    public init(shape: S, tint: Color? = nil) {
        self.shape = shape
        self.tint = tint
    }

    private var resolved: ResolvedGlass {
        resolveGlass(
            reduceTransparency: reduceTransparency,
            increaseContrast: contrast == .increased
        )
    }

    public func body(content: Content) -> some View {
        switch resolved {
        case .identity:
            // Opaque fallback: a solid fill behind the content, no live material.
            content.background { shape.fill(Palette.contentBackground) }
        case .regular, .clear:
            // Decorative surfaces use the regular material (with optional tint).
            content.glassEffect(glass, in: shape)
        }
    }

    private var glass: Glass {
        if let tint { return .regular.tint(tint) }
        return .regular
    }
}

@available(iOS 26.0, macOS 26.0, *)
public extension View {
    /// Apply an accessible decorative glass material in `shape`. Drops to a solid
    /// opaque background under Reduce Transparency / Increased Contrast.
    func glassStyle(in shape: some Shape = Capsule(), tint: Color? = nil) -> some View {
        modifier(DecorativeGlassModifier(shape: shape, tint: tint))
    }
}
