import SwiftUI

@available(iOS 26.0, macOS 26.0, *)
public struct GlassScrim: ViewModifier {
    private let cornerRadius: CGFloat

    public init(cornerRadius: CGFloat = CornerRadius.md) {
        self.cornerRadius = cornerRadius
    }

    public func body(content: Content) -> some View {
        let shape = RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
        content.modifier(VaultSurfaceBackground(role: .content, shape: shape))
    }
}

@available(iOS 26.0, macOS 26.0, *)
public extension View {
    /// Render a solid semantic content surface behind sensitive content.
    func glassScrim(cornerRadius: CGFloat = CornerRadius.md) -> some View {
        modifier(GlassScrim(cornerRadius: cornerRadius))
    }
}
