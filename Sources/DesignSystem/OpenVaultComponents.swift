import SwiftUI

// MARK: - Brand mark

@available(iOS 26.0, macOS 26.0, *)
public struct OpenVaultMark: View {
    private let size: CGFloat

    public init(size: CGFloat = 86) {
        self.size = size
    }

    public var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: size * 0.255, style: .continuous)
                .fill(
                    LinearGradient(
                        colors: [
                            Color(red: 90 / 255, green: 107 / 255, blue: 140 / 255),
                            Color(red: 49 / 255, green: 59 / 255, blue: 82 / 255),
                            Color(red: 37 / 255, green: 45 / 255, blue: 64 / 255)
                        ],
                        startPoint: .top,
                        endPoint: .bottom
                    )
                )
                .overlay(alignment: .top) {
                    Ellipse()
                        .fill(.white.opacity(0.2))
                        .frame(width: size * 0.8, height: size * 0.42)
                        .blur(radius: size * 0.12)
                        .offset(y: -size * 0.16)
                        .clipped()
                }
                .overlay {
                    RoundedRectangle(cornerRadius: size * 0.255, style: .continuous)
                        .stroke(.white.opacity(0.18), lineWidth: 0.5)
                }
                .shadow(color: .black.opacity(0.45), radius: size * 0.22, y: size * 0.12)

            Image(systemName: "lock.shield")
                .font(.system(size: size * 0.43, weight: .regular))
                .symbolRenderingMode(.monochrome)
                .foregroundStyle(.white.opacity(0.94))
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}

// MARK: - Brand badge

@available(iOS 26.0, macOS 26.0, *)
public struct BrandBadge: View {
    private let title: String
    private let diameter: CGFloat

    public init(_ title: String, diameter: CGFloat = 32) {
        self.title = title
        self.diameter = diameter
    }

    public var body: some View {
        ZStack {
            Circle().fill(spec.color)
            Text(spec.glyph)
                .font(.system(size: diameter * spec.fontScale, weight: .semibold, design: .rounded))
                .foregroundStyle(spec.foreground)
                .minimumScaleFactor(0.55)
                .lineLimit(1)
                .padding(diameter * 0.12)
        }
        .frame(width: diameter, height: diameter)
        .overlay {
            if spec.needsBorder {
                Circle().stroke(.white.opacity(0.16), lineWidth: 0.5)
            }
        }
        .accessibilityHidden(true)
    }

    private var spec: BrandSpec { BrandSpec(title: title) }
}

private struct BrandSpec {
    let glyph: String
    let color: Color
    let foreground: Color
    let fontScale: CGFloat
    let needsBorder: Bool

    init(title: String) {
        let value = title.folding(options: [.caseInsensitive, .diacriticInsensitive], locale: .current)
            .lowercased()
        switch value {
        case let text where text.contains("github"):
            self.init("G", Color(red: 27 / 255, green: 31 / 255, blue: 35 / 255), .white, 0.48, true)
        case let text where text.contains("google"):
            self.init("G", Color(red: 66 / 255, green: 133 / 255, blue: 244 / 255), .white, 0.48, false)
        case let text where text.contains("微信") || text.contains("wechat"):
            self.init("微", Color(red: 7 / 255, green: 193 / 255, blue: 96 / 255), .white, 0.42, false)
        case let text where text.contains("支付宝") || text.contains("alipay"):
            self.init("支", Color(red: 22 / 255, green: 119 / 255, blue: 1), .white, 0.45, false)
        case let text where text.contains("dropbox"):
            self.init("D", Color(red: 0, green: 97 / 255, blue: 1), .white, 0.48, false)
        case let text where text.contains("steam"):
            self.init("S", Color(red: 23 / 255, green: 26 / 255, blue: 33 / 255), .white, 0.48, true)
        case let text where text.contains("microsoft") || text.contains("微软"):
            self.init("M", Color(red: 0, green: 103 / 255, blue: 184 / 255), .white, 0.46, false)
        case let text where text.contains("netflix"):
            self.init("N", Color(red: 20 / 255, green: 20 / 255, blue: 20 / 255), Color(red: 229 / 255, green: 9 / 255, blue: 20 / 255), 0.5, true)
        case let text where text.contains("apple") || text.contains("icloud"):
            self.init("A", Color(red: 169 / 255, green: 174 / 255, blue: 184 / 255), .white, 0.46, false)
        case let text where text.contains("wifi") || text.contains("wi-fi"):
            self.init("W", Palette.cyan, .white, 0.42, false)
        default:
            let first = title.trimmingCharacters(in: .whitespacesAndNewlines).first
                .map { String($0).uppercased() } ?? "•"
            self.init(first, Palette.indigo, .white, 0.46, false)
        }
    }

    private init(_ glyph: String, _ color: Color, _ foreground: Color,
                 _ fontScale: CGFloat, _ needsBorder: Bool) {
        self.glyph = glyph
        self.color = color
        self.foreground = foreground
        self.fontScale = fontScale
        self.needsBorder = needsBorder
    }
}

// MARK: - Opaque cards

@available(iOS 26.0, macOS 26.0, *)
public struct OpenVaultCard<Content: View>: View {
    private let cornerRadius: CGFloat
    private let padding: CGFloat
    private let content: Content

    public init(cornerRadius: CGFloat = CornerRadius.iPhoneCard,
                padding: CGFloat = Spacing.lg,
                @ViewBuilder content: () -> Content) {
        self.cornerRadius = cornerRadius
        self.padding = padding
        self.content = content()
    }

    public var body: some View {
        content
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background {
                RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                    .fill(Palette.contentBackground)
            }
    }
}

@available(iOS 26.0, macOS 26.0, *)
public struct OpenVaultSectionTitle: View {
    private let title: LocalizedStringKey

    public init(_ title: LocalizedStringKey) { self.title = title }

    public var body: some View {
        Text(title)
            .font(.title3.weight(.bold))
            .foregroundStyle(Palette.primaryText)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, Spacing.lg)
    }
}

// MARK: - TOTP countdown

@available(iOS 26.0, macOS 26.0, *)
public struct CountdownRing: View {
    private let progress: Double
    private let size: CGFloat
    private let lineWidth: CGFloat
    private let tint: Color

    public init(progress: Double, size: CGFloat = 20, lineWidth: CGFloat = 2.6,
                tint: Color = Palette.teal) {
        self.progress = min(max(progress, 0), 1)
        self.size = size
        self.lineWidth = lineWidth
        self.tint = tint
    }

    public var body: some View {
        ZStack {
            Circle().stroke(Palette.separator.opacity(0.55), lineWidth: lineWidth)
            Circle()
                .trim(from: 0, to: progress)
                .stroke(tint, style: StrokeStyle(lineWidth: lineWidth, lineCap: .round))
                .rotationEffect(.degrees(-90))
                .animation(.linear(duration: 0.25), value: progress)
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}

// MARK: - Copy feedback

@available(iOS 26.0, macOS 26.0, *)
public struct GlassToast: View {
    private let message: String

    public init(_ message: String) { self.message = message }

    public var body: some View {
        Label(message, systemImage: "checkmark.circle.fill")
            .font(.subheadline.weight(.semibold))
            .foregroundStyle(Palette.primaryText)
            .symbolRenderingMode(.palette)
            .foregroundStyle(Palette.success, Palette.success.opacity(0.16))
            .padding(.horizontal, Spacing.lg)
            .frame(minHeight: 44)
            .glassStyle(in: Capsule())
            .shadow(color: .black.opacity(0.16), radius: 16, y: 8)
            .accessibilityAddTraits([.isStaticText, .updatesFrequently])
    }
}
