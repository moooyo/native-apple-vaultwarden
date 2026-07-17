import SwiftUI

// MARK: - GlassScrim
//
// An opaque scrim behind sensitive content. WWDC26's revised hierarchy keeps Liquid
// Glass on navigation and control chrome only; passwords, card numbers and OTP secrets
// always sit on a solid content surface.
//
// Use via the `.glassScrim(cornerRadius:)` modifier as a background for sensitive UI.

@available(iOS 26.0, macOS 26.0, *)
public struct GlassScrim: ViewModifier {
    private let cornerRadius: CGFloat

    public init(cornerRadius: CGFloat = CornerRadius.md) {
        self.cornerRadius = cornerRadius
    }

    public func body(content: Content) -> some View {
        let shape = RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
        return content
            .background { shape.fill(Palette.contentBackground) }
            .overlay { shape.stroke(Palette.separator.opacity(0.35), lineWidth: 0.5) }
    }
}

@available(iOS 26.0, macOS 26.0, *)
public extension View {
    /// Render a solid semantic content surface behind sensitive content.
    func glassScrim(cornerRadius: CGFloat = CornerRadius.md) -> some View {
        modifier(GlassScrim(cornerRadius: cornerRadius))
    }
}
