import SwiftUI

@available(*, deprecated, message: "Use glassStyle(in:) for floating accessories or glassScrim() for content.")
public enum ResolvedGlass: Equatable, Sendable {
    case regular, clear, identity

    fileprivate init(_ material: VaultSurfaceMaterial) {
        self = material == .opaque ? .identity : .regular
    }

    /// Only a client explicitly requesting clear glass can select it; neither resolver does.
    @available(iOS 26.0, macOS 26.0, *)
    public var glass: Glass {
        switch self {
        case .regular: .regular
        case .clear: .clear
        case .identity: .identity
        }
    }
}

@available(*, deprecated, message: "Use glassStyle(in:) for floating accessories.")
public func resolveGlass(reduceTransparency: Bool, increaseContrast: Bool) -> ResolvedGlass {
    ResolvedGlass(VaultSurfaceRole.floatingAccessory.material(reduceTransparency: reduceTransparency,
                                                              increaseContrast: increaseContrast))
}

@available(*, deprecated, message: "Use glassScrim() for opaque sensitive content.")
public func resolveSensitiveGlass(reduceTransparency: Bool, increaseContrast: Bool) -> ResolvedGlass {
    ResolvedGlass(VaultSurfaceRole.content.material(reduceTransparency: reduceTransparency,
                                                    increaseContrast: increaseContrast))
}

@available(iOS 26.0, macOS 26.0, *)
@available(*, deprecated, message: "Use glassStyle(in:); the system controls the material.")
public struct DecorativeGlassModifier<S: Shape>: ViewModifier {
    private let shape: S

    public init(shape: S, tint _: Color? = nil) { self.shape = shape }
    public func body(content: Content) -> some View { content.glassStyle(in: shape) }
}

private struct LegacyGlassTintKey: EnvironmentKey {
    static let defaultValue = 0.68
}

public extension OpenVaultPreferenceKey {
    @available(*, deprecated, message: "OpenVault now follows the system's Liquid Glass settings.")
    static let glassTint = "openvault.appearance.glassTint"
}

public extension EnvironmentValues {
    /// Preserved for clients that store this preference; it has no effect on OpenVault materials.
    @available(*, deprecated, message: "OpenVault now follows the system's Liquid Glass settings.")
    var openVaultGlassTint: Double {
        get { self[LegacyGlassTintKey.self] }
        set { self[LegacyGlassTintKey.self] = min(max(newValue, 0), 1) }
    }
}

@available(iOS 26.0, macOS 26.0, *)
public extension View {
    @available(*, deprecated, message: "Use glassStyle(in:); the system controls the material.")
    func glassStyle(in shape: some Shape = Capsule(), tint _: Color?) -> some View {
        glassStyle(in: shape)
    }

    @available(*, deprecated, message: "OpenVault now follows the system's Liquid Glass settings.")
    func openVaultGlassTint(_ value: Double) -> some View {
        environment(\.openVaultGlassTint, value)
    }
}
