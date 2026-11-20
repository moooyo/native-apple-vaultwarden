import SwiftUI

@available(iOS 26.0, macOS 26.0, *)
struct VaultSurfaceBackground<S: Shape>: ViewModifier {
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
    @Environment(\.colorSchemeContrast) private var contrast

    let role: VaultSurfaceRole
    let shape: S

    func body(content: Content) -> some View {
        switch role.material(reduceTransparency: reduceTransparency, increaseContrast: contrast == .increased) {
        case .opaque:
            content
                .background(Palette.contentBackground, in: shape)
                .overlay { shape.stroke(Palette.separator, lineWidth: 1).allowsHitTesting(false) }
        case .regularGlass:
            content.glassEffect(.regular, in: shape)
        }
    }
}

@available(iOS 26.0, macOS 26.0, *)
public extension View {
    /// For custom floating accessories only. Native controls supply their own material.
    func glassStyle(in shape: some Shape = Capsule()) -> some View {
        modifier(VaultSurfaceBackground(role: .floatingAccessory, shape: shape))
    }
}
