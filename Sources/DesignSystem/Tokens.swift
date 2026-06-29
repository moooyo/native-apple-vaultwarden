import SwiftUI

// MARK: - Design tokens
//
// A small, semantic token set so screens never hard-code magic numbers. Values are
// tuned for a 8-pt grid consistent with iOS/macOS 26. All tokens are plain values so
// they are trivially usable from any target and (for the numeric ones) testable.

/// Spacing scale (8-pt grid with a couple of half-steps).
public enum Spacing {
    public static let xxs: CGFloat = 2
    public static let xs: CGFloat = 4
    public static let sm: CGFloat = 8
    public static let md: CGFloat = 12
    public static let lg: CGFloat = 16
    public static let xl: CGFloat = 24
    public static let xxl: CGFloat = 32
}

/// Corner-radius scale. Cards use `card`; the value also feeds `ConcentricRectangle`
/// so nested shapes stay visually concentric.
public enum CornerRadius {
    public static let sm: CGFloat = 8
    public static let md: CGFloat = 12
    public static let card: CGFloat = 16
    public static let lg: CGFloat = 20
    /// Capsule-ish; use `Capsule` directly when you want a true capsule.
    public static let pill: CGFloat = 999
}

/// Semantic colors. We lean on system colors so Dark Mode / Increased Contrast are
/// handled for free; only the brand accents are custom.
public enum Palette {
    /// Primary brand accent (Tessera mosaic blue). Defined per-platform from system
    /// tints so it adapts to appearance automatically; replace with an asset catalog
    /// color in the app target if a bespoke brand color is required.
    public static let accent: Color = .accentColor

    /// Background for opaque content layers (list rows, card content).
    #if os(iOS)
    public static let contentBackground: Color = Color(uiColor: .secondarySystemGroupedBackground)
    public static let groupedBackground: Color = Color(uiColor: .systemGroupedBackground)
    public static let primaryText: Color = Color(uiColor: .label)
    public static let secondaryText: Color = Color(uiColor: .secondaryLabel)
    public static let separator: Color = Color(uiColor: .separator)
    #elseif os(macOS)
    public static let contentBackground: Color = Color(nsColor: .controlBackgroundColor)
    public static let groupedBackground: Color = Color(nsColor: .windowBackgroundColor)
    public static let primaryText: Color = Color(nsColor: .labelColor)
    public static let secondaryText: Color = Color(nsColor: .secondaryLabelColor)
    public static let separator: Color = Color(nsColor: .separatorColor)
    #else
    public static let contentBackground: Color = .gray.opacity(0.12)
    public static let groupedBackground: Color = .gray.opacity(0.06)
    public static let primaryText: Color = .primary
    public static let secondaryText: Color = .secondary
    public static let separator: Color = .gray.opacity(0.3)
    #endif

    // Status accents (also used by the strength helper).
    public static let danger: Color = .red
    public static let warning: Color = .orange
    public static let caution: Color = .yellow
    public static let success: Color = .green
}

/// Typography helpers — semantic font roles mapped onto Dynamic Type text styles so
/// the app scales with the user's preferred content size automatically.
public enum Typography {
    public static let screenTitle: Font = .largeTitle.weight(.bold)
    public static let sectionTitle: Font = .title3.weight(.semibold)
    public static let rowTitle: Font = .body
    public static let rowSubtitle: Font = .subheadline
    public static let caption: Font = .caption

    /// Monospaced face for codes (TOTP, card numbers) so digits align and don't jump.
    public static let code: Font = .system(.title2, design: .monospaced).weight(.semibold)
    public static let secretValue: Font = .system(.body, design: .monospaced)
}
