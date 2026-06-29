import SwiftUI

// MARK: - SecureRevealView
//
// Tap-to-reveal for a password / TOTP / card number. Security + Liquid Glass intent:
//
//   * SECURITY REQUIREMENT: the revealed value is rendered on a `.regular` Liquid
//     Glass material or a SOLID scrim — NEVER on `.clear` glass. Putting a copyable
//     secret on clear glass over a busy background makes it both unreadable and
//     shoulder-surf-prone. This is enforced via `GlassScrim`, whose
//     `resolveSensitiveGlass(...)` decision provably never returns `.clear`.
//   * When hidden, we show dots (•) so the field's presence/length-feel is conveyed
//     without exposing the value.
//   * Accessibility: under Reduce Transparency / Increased Contrast the scrim drops to
//     an opaque solid background automatically (see GlassScrim).
//
// Clipboard policy: this view NEVER touches the clipboard. It exposes an optional
// `onCopy` closure; the host (which knows the platform pasteboard + clear-after
// policy) performs the copy. This keeps DesignSystem free of UIPasteboard/NSPasteboard
// and platform pasteboard concerns.
//
// Reveal state: this is a *controlled component* — the reveal toggle is driven by an
// `isRevealed` `@Binding` owned by the caller (typically an @Observable view model in
// UIShared). This keeps reveal state observable/auditable by the model layer (e.g. to
// auto-hide on lock or after a timeout) rather than trapped in private view state.
// `SecureRevealCard` below is a convenience that owns the state for simple call sites.

@available(iOS 26.0, macOS 26.0, *)
public struct SecureRevealView: View {
    private let title: String
    private let value: String
    /// When true the value is shown in a monospaced face (passwords, card numbers).
    private let isMonospaced: Bool
    /// Called when the user taps copy. The view does NOT copy itself.
    private let onCopy: (() -> Void)?

    @Binding private var isRevealed: Bool

    /// - Parameters:
    ///   - title: accessibility label / field caption (e.g. "Password").
    ///   - value: the secret value to reveal.
    ///   - isRevealed: binding controlling whether the value is shown.
    ///   - isMonospaced: render the revealed value monospaced (default true).
    ///   - onCopy: optional copy callback; the view never touches the clipboard.
    public init(
        title: String,
        value: String,
        isRevealed: Binding<Bool>,
        isMonospaced: Bool = true,
        onCopy: (() -> Void)? = nil
    ) {
        self.title = title
        self.value = value
        self._isRevealed = isRevealed
        self.isMonospaced = isMonospaced
        self.onCopy = onCopy
    }

    private var displayString: String {
        isRevealed ? value : String(repeating: "•", count: min(max(value.count, 1), 16))
    }

    public var body: some View {
        HStack(spacing: Spacing.md) {
            VStack(alignment: .leading, spacing: Spacing.xxs) {
                Text(title)
                    .font(Typography.caption)
                    .foregroundStyle(Palette.secondaryText)
                Text(displayString)
                    .font(isMonospaced ? Typography.secretValue : Typography.rowTitle)
                    .foregroundStyle(Palette.primaryText)
                    .textSelection(.enabled)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .accessibilityLabel(title)
                    .accessibilityValue(isRevealed ? value : "Hidden")
            }
            Spacer(minLength: Spacing.sm)

            Button {
                isRevealed.toggle()
            } label: {
                Image(systemName: isRevealed ? "eye.slash" : "eye")
                    .imageScale(.medium)
            }
            .buttonStyle(.glass)
            .accessibilityLabel(isRevealed ? "Hide \(title)" : "Reveal \(title)")

            if let onCopy {
                Button {
                    onCopy()
                } label: {
                    Image(systemName: "doc.on.doc")
                        .imageScale(.medium)
                }
                .buttonStyle(.glass)
                .accessibilityLabel("Copy \(title)")
            }
        }
        .padding(.horizontal, Spacing.md)
        .padding(.vertical, Spacing.sm)
        // SECURITY: revealed secret always sits on a regular-material / solid scrim,
        // never clear glass. The scrim degrades to opaque under accessibility flags.
        .glassScrim(cornerRadius: CornerRadius.md)
    }
}
