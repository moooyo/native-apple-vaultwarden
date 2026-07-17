import SwiftUI

// MARK: - OpenVault design tokens
//
// Values mirror the WWDC26 handoff. System semantic colours remain the source of truth
// so light/dark mode, increased contrast and Dynamic Type continue to work naturally.

/// Spacing scale (8-pt grid with a couple of half-steps).
public enum Spacing {
    public static let xxs: CGFloat = 2
    public static let xs: CGFloat = 4
    public static let sm: CGFloat = 8
    public static let md: CGFloat = 12
    public static let lg: CGFloat = 16
    public static let xl: CGFloat = 24
    public static let xxl: CGFloat = 32
    public static let xxxl: CGFloat = 40
}

/// Corner-radius scale. Cards use `card`; the value also feeds `ConcentricRectangle`
/// so nested shapes stay visually concentric.
public enum CornerRadius {
    public static let settingIcon: CGFloat = 7
    public static let sm: CGFloat = 8
    public static let md: CGFloat = 12
    public static let button: CGFloat = 14
    public static let card: CGFloat = 18
    public static let lg: CGFloat = 20
    public static let statistic: CGFloat = 22
    public static let iPhoneCard: CGFloat = 26
    public static let iPadCard: CGFloat = 18
    public static let macCard: CGFloat = 12
    /// Capsule-ish; use `Capsule` directly when you want a true capsule.
    public static let pill: CGFloat = 999
}

/// Semantic colors. We lean on system colors so Dark Mode / Increased Contrast are
/// handled for free; only the brand accents are custom.
public enum Palette {
    public static let accent: Color = .blue
    public static let teal: Color = .teal
    public static let cyan: Color = .cyan
    public static let indigo: Color = .indigo
    public static let purple: Color = .purple

    /// Background for opaque content layers (list rows, card content).
    #if os(iOS)
    public static let contentBackground: Color = Color(uiColor: .secondarySystemGroupedBackground)
    public static let groupedBackground: Color = Color(uiColor: .systemGroupedBackground)
    public static let primaryText: Color = Color(uiColor: .label)
    public static let secondaryText: Color = Color(uiColor: .secondaryLabel)
    public static let tertiaryText: Color = Color(uiColor: .tertiaryLabel)
    public static let separator: Color = Color(uiColor: .separator)
    public static let controlFill: Color = Color(uiColor: .tertiarySystemFill)
    #elseif os(macOS)
    public static let contentBackground: Color = Color(nsColor: .controlBackgroundColor)
    public static let groupedBackground: Color = Color(nsColor: .windowBackgroundColor)
    public static let primaryText: Color = Color(nsColor: .labelColor)
    public static let secondaryText: Color = Color(nsColor: .secondaryLabelColor)
    public static let tertiaryText: Color = Color(nsColor: .tertiaryLabelColor)
    public static let separator: Color = Color(nsColor: .separatorColor)
    public static let controlFill: Color = Color(nsColor: .unemphasizedSelectedContentBackgroundColor)
    #else
    public static let contentBackground: Color = .gray.opacity(0.12)
    public static let groupedBackground: Color = .gray.opacity(0.06)
    public static let primaryText: Color = .primary
    public static let secondaryText: Color = .secondary
    public static let tertiaryText: Color = .secondary.opacity(0.72)
    public static let separator: Color = .gray.opacity(0.3)
    public static let controlFill: Color = .gray.opacity(0.12)
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
    public static let fieldLabel: Font = .caption
    public static let tabLabel: Font = .caption2.weight(.semibold)
    public static let action: Font = .body.weight(.semibold)

    /// Monospaced face for codes (TOTP, card numbers) so digits align and don't jump.
    public static let code: Font = .system(.title2, design: .monospaced).weight(.semibold)
    public static let secretValue: Font = .system(.body, design: .monospaced)
}

/// Shared persistence keys used by both platform shells.
public enum OpenVaultPreferenceKey {
    public static let glassTint = "openvault.appearance.glassTint"
    public static let theme = "openvault.appearance.theme"
    public static let clipboardTimeout = "openvault.security.clipboardTimeout"
}

public enum OpenVaultTheme: String, CaseIterable, Identifiable {
    case system, light, dark

    public var id: String { rawValue }

    public var colorScheme: ColorScheme? {
        switch self {
        case .system: nil
        case .light: .light
        case .dark: .dark
        }
    }
}
