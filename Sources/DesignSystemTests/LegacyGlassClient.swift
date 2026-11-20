import DesignSystem
import SwiftUI

// Compile as a client of the public API, without @testable access.
@available(*, deprecated)
private struct LegacyGlassClient: View {
    @AppStorage(OpenVaultPreferenceKey.glassTint) var tint = 0.68
    @Environment(\.openVaultGlassTint) var inheritedTint

    var body: some View {
        let surface = resolveGlass(reduceTransparency: false, increaseContrast: false)
        let secret = resolveSensitiveGlass(reduceTransparency: true, increaseContrast: false)
        VStack {
            Text("A").glassEffect(surface.glass)
            Text("B").glassEffect(secret.glass)
            Text("C").glassStyle().glassStyle(in: Circle())
            Text("D").glassStyle(tint: .blue)
            Text("E").glassStyle(in: Circle(), tint: nil)
            Text("F").modifier(DecorativeGlassModifier(shape: Capsule(), tint: .blue))
            Text("G").glassEffect(ResolvedGlass.clear.glass)
        }
        .openVaultGlassTint(tint)
    }
}
