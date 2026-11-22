import Accessibility
import SwiftUI

// MARK: - Brand mark

@available(iOS 26.0, macOS 26.0, *)
public struct OpenVaultMark: View {
    private let size: CGFloat

    public init(size: CGFloat = 86) {
        self.size = size
    }

    public var body: some View {
        Image("OpenVaultMark", bundle: .module)
            .renderingMode(.original)
            .resizable()
            .scaledToFit()
            .frame(width: size, height: size)
            .clipShape(RoundedRectangle(cornerRadius: size * 0.23, style: .continuous))
            .accessibilityHidden(true)
    }
}

// MARK: - Brand badge

@available(iOS 26.0, macOS 26.0, *)
public struct BrandBadge: View {
    public enum Style { case account, note, card, identity, terminal }

    @Environment(\.colorScheme) private var colorScheme
    @Environment(\.colorSchemeContrast) private var contrast
    private let spec: BrandSpec
    private let diameter: CGFloat

    public init(_ title: String, diameter: CGFloat = 32, style: Style = .account) {
        self.spec = BrandSpec(title: title, style: style)
        self.diameter = diameter
    }

    public var body: some View {
        let shape = RoundedRectangle(cornerRadius: diameter * 0.28, style: .continuous)
        let darkContrast = colorScheme == .dark && contrast == .increased
        ZStack {
            shape.fill(spec.color)
            Text(spec.glyph)
                .font(.system(size: diameter * spec.fontScale, weight: .semibold, design: .rounded))
                .foregroundStyle(spec.foreground ?? (darkContrast ? Color.black : .white))
                .minimumScaleFactor(0.55)
                .lineLimit(1)
                .padding(diameter * 0.12)
        }
        .frame(width: diameter, height: diameter)
        .overlay {
            if spec.needsBorder || colorScheme == .dark {
                shape.strokeBorder(.white.opacity(darkContrast ? 0.55 : 0.2), lineWidth: 1)
            }
        }
        .accessibilityHidden(true)
    }
}

private struct BrandSpec {
    let glyph: String
    let color: Color
    let foreground: Color?
    let fontScale: CGFloat
    let needsBorder: Bool

    init(title: String, style: BrandBadge.Style) {
        let value = title.folding(options: [.caseInsensitive, .diacriticInsensitive], locale: .current)
            .lowercased()
        let initial = title.trimmingCharacters(in: .whitespacesAndNewlines).first
            .map { String($0).uppercased() } ?? "•"
        switch style {
        case .note:
            let wifi = ["wifi", "wi-fi", "wi‑fi"].contains(where: value.contains)
            self.init(wifi ? "W" : "笔", wifi ? .cyan : .orange, nil, 0.46, false)
            return
        case .card:
            self.init("卡", .indigo, nil, 0.46, false)
            return
        case .identity:
            self.init(initial, .purple, nil, 0.46, false)
            return
        case .terminal:
            self.init(">", .gray, nil, 0.48, false)
            return
        case .account: break
        }
        switch value {
        case let text where text.contains("github"):
            self.init("G", Color(red: 27 / 255, green: 31 / 255, blue: 35 / 255), .white, 0.48, true)
        case let text where text.contains("google"):
            self.init("G", Color(red: 58 / 255, green: 120 / 255, blue: 224 / 255), .white, 0.48, false)
        case let text where text.contains("gitlab"):
            self.init("G", Color(red: 194 / 255, green: 65 / 255, blue: 12 / 255), .white, 0.48, false)
        case let text where text.contains("微信") || text.contains("wechat"):
            self.init("微", Color(red: 7 / 255, green: 163 / 255, blue: 90 / 255), .white, 0.42, false)
        case let text where text.contains("支付宝") || text.contains("alipay"):
            self.init("支", Color(red: 22 / 255, green: 104 / 255, blue: 227 / 255), .white, 0.45, false)
        case let text where text.contains("dropbox"):
            self.init("D", Color(red: 0, green: 97 / 255, blue: 1), .white, 0.48, false)
        case let text where text.contains("steam"):
            self.init("S", Color(red: 23 / 255, green: 26 / 255, blue: 33 / 255), .white, 0.48, true)
        case let text where text.contains("microsoft") || text.contains("微软"):
            self.init("M", Color(red: 0, green: 103 / 255, blue: 184 / 255), .white, 0.46, false)
        case let text where text.contains("netflix"):
            self.init("N", Color(red: 20 / 255, green: 20 / 255, blue: 20 / 255), Color(red: 229 / 255, green: 9 / 255, blue: 20 / 255), 0.5, true)
        case let text where text.contains("apple") || text.contains("icloud"):
            self.init("A", Color(red: 108 / 255, green: 108 / 255, blue: 114 / 255), .white, 0.46, false)
        case let text where text.contains("wifi") || text.contains("wi-fi"):
            self.init("W", Palette.cyan, .white, 0.42, false)
        default:
            self.init(initial, Palette.indigo, nil, 0.46, false)
        }
    }

    private init(_ glyph: String, _ color: Color, _ foreground: Color?,
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
            .font(Typography.sectionTitle)
            .foregroundStyle(Palette.primaryText)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, Spacing.lg)
    }
}

// MARK: - Copy feedback

@available(iOS 26.0, macOS 26.0, *)
public struct GlassToast: View {
    private let message: String

    public init(_ message: String) { self.message = message }

    public var body: some View {
        Label(message, systemImage: "checkmark.circle")
            .labelStyle(.titleAndIcon)
            .font(.subheadline.weight(.semibold))
            .foregroundStyle(.primary)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.horizontal, Spacing.lg)
            .padding(.vertical, Spacing.sm)
            .frame(minHeight: 44)
            .glassStyle(in: Capsule())
            .allowsHitTesting(false)
            .onChange(of: message, initial: true) { _, message in
                AccessibilityNotification.Announcement(message).post()
            }
    }
}

@available(iOS 26.0, macOS 26.0, *)
private struct CopyToastModifier: ViewModifier {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    let message: String?
    let bottomInset: CGFloat

    func body(content: Content) -> some View {
        content.overlay(alignment: .bottom) {
            ZStack {
                if let message {
                    GlassToast(message)
                        .transition(reduceMotion ? .opacity : .move(edge: .bottom).combined(with: .opacity))
                }
            }
            .animation(.easeOut(duration: 0.2), value: message)
            .padding(.horizontal, Spacing.lg)
            .padding(.bottom, bottomInset)
            .allowsHitTesting(false)
        }
    }
}

@available(iOS 26.0, macOS 26.0, *)
public extension View {
    /// Present a short status message without obscuring interaction or speaking the copied value.
    func copyToast(_ message: String?, bottomInset: CGFloat = Spacing.xl) -> some View {
        modifier(CopyToastModifier(message: message, bottomInset: bottomInset))
    }
}
