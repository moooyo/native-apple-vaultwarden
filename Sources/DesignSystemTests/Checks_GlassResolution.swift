import Foundation
@testable import DesignSystem

func checkGlassResolution(_ r: inout TestRunner) {
    // --- resolveGlass: Reduce Transparency always wins ---
    r.expect(resolveGlass(reduceTransparency: true, increaseContrast: false), .identity,
             "reduceTransparency true -> identity")
    r.expect(resolveGlass(reduceTransparency: true, increaseContrast: true), .identity,
             "reduceTransparency true + contrast -> identity")

    // --- resolveGlass: Increase Contrast also flattens decorative surfaces ---
    r.expect(resolveGlass(reduceTransparency: false, increaseContrast: true), .identity,
             "increaseContrast true -> identity")

    // --- resolveGlass: neither flag -> regular live glass ---
    r.expect(resolveGlass(reduceTransparency: false, increaseContrast: false), .regular,
             "no flags -> regular")

    // --- resolveSensitiveGlass: never clear; regular when allowed, identity otherwise ---
    r.expect(resolveSensitiveGlass(reduceTransparency: false, increaseContrast: false), .regular,
             "sensitive no flags -> regular")
    r.expect(resolveSensitiveGlass(reduceTransparency: true, increaseContrast: false), .identity,
             "sensitive reduceTransparency -> identity")
    r.expect(resolveSensitiveGlass(reduceTransparency: false, increaseContrast: true), .identity,
             "sensitive increaseContrast -> identity")

    // Security invariant: sensitive resolution NEVER yields .clear for any flag combo.
    var neverClear = true
    for rt in [false, true] {
        for ic in [false, true] {
            if resolveSensitiveGlass(reduceTransparency: rt, increaseContrast: ic) == .clear {
                neverClear = false
            }
        }
    }
    r.expectTrue(neverClear, "sensitive resolution never returns .clear")
}
