import SwiftUI

// MARK: - Pure glass-style resolution (testable, no SwiftUI environment needed)
//
// Liquid Glass intent & accessibility contract
// --------------------------------------------
// `.glassEffect()` is only applied to genuinely custom surfaces (standard controls
// already get the material from the system on recompile). On those custom surfaces
// we MUST honor the user's accessibility preferences:
//
//   * Reduce Transparency  → drop to `.identity` (no glass / opaque). Apple's own
//     guidance and the iOS 27 transparency slider make this the single most
//     important fallback. Reduce Transparency always wins.
//   * Increased Contrast   → for *decorative* surfaces we also flatten to `.identity`
//     so foreground/background contrast is maximised; the caller layers a solid
//     background underneath.
//
// The decision is factored out of any View so it can be unit-tested headlessly
// (SwiftUI Views cannot be exercised without a render host). See DesignSystemTests.

/// The kind of resolved surface we want to render, independent of SwiftUI types.
///
/// This mirrors the `Glass` variants we actually use but is a plain `enum` so it is
/// `Equatable` and trivially testable.
public enum ResolvedGlass: Equatable, Sendable {
    /// A live `.regular` Liquid Glass material (refracts/blurs the content behind it).
    case regular
    /// A live `.clear` Liquid Glass material. NEVER used for sensitive content.
    case clear
    /// No glass effect at all — render opaque. The accessible fallback.
    case identity
}

/// Resolve which glass surface a *decorative* custom surface should use given the
/// two accessibility flags that affect material rendering.
///
/// Rules (in priority order):
///   1. Reduce Transparency on  → `.identity` (opaque). Highest priority.
///   2. Increase Contrast on    → `.identity` (opaque) for decorative surfaces.
///   3. Otherwise               → `.regular`.
///
/// - Parameters:
///   - reduceTransparency: value of `\.accessibilityReduceTransparency`.
///   - increaseContrast: `true` when `\.colorSchemeContrast == .increased`.
/// - Returns: the surface to render.
public func resolveGlass(reduceTransparency: Bool, increaseContrast: Bool) -> ResolvedGlass {
    if reduceTransparency { return .identity }
    if increaseContrast { return .identity }
    return .regular
}

/// Resolve the glass surface for a *sensitive* surface (a revealed password / OTP /
/// card number). The security requirement is absolute: such content is NEVER allowed
/// on `.clear` glass because a busy background underneath would make it both
/// unreadable and shoulder-surf-prone. So a sensitive surface is only ever `.regular`
/// (when transparency is allowed) or `.identity`/opaque (otherwise) — never `.clear`.
///
/// - Returns: `.regular` when live glass is allowed, else `.identity` (caller draws a
///   solid scrim). The function provably never returns `.clear`.
public func resolveSensitiveGlass(reduceTransparency: Bool, increaseContrast: Bool) -> ResolvedGlass {
    let resolved = resolveGlass(reduceTransparency: reduceTransparency, increaseContrast: increaseContrast)
    // Defensive: even if `resolveGlass` ever returned `.clear`, force it off here.
    return resolved == .clear ? .regular : resolved
}

#if canImport(SwiftUI)
@available(iOS 26.0, macOS 26.0, *)
public extension ResolvedGlass {
    /// Bridge to a concrete SwiftUI `Glass` value for `.glassEffect(_:in:)`.
    var glass: Glass {
        switch self {
        case .regular: return .regular
        case .clear: return .clear
        case .identity: return .identity
        }
    }
}
#endif
