@testable import DesignSystem

func checkGlassResolution(_ r: inout TestRunner) {
    let cases: [(Bool, Bool, VaultSurfaceMaterial)] = [
        (false, false, .regularGlass),
        (true, false, .opaque),
        (false, true, .opaque),
        (true, true, .opaque),
    ]
    for (reduceTransparency, increaseContrast, accessoryMaterial) in cases {
        let flags = "reduceTransparency=\(reduceTransparency), increaseContrast=\(increaseContrast)"
        r.expect(VaultSurfaceRole.floatingAccessory.material(reduceTransparency: reduceTransparency,
                                                             increaseContrast: increaseContrast),
                 accessoryMaterial, "floating accessory: \(flags)")
        r.expect(VaultSurfaceRole.content.material(reduceTransparency: reduceTransparency,
                                                    increaseContrast: increaseContrast),
                 .opaque, "vault content stays opaque: \(flags)")
    }
}
