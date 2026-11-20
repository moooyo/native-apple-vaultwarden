import SwiftUI

// MARK: - SecureRevealView
//
// Tap-to-reveal for a password / TOTP / card number. Security + Liquid Glass intent:
//
//   * SECURITY REQUIREMENT: the revealed value is rendered on a SOLID content surface.
//     Liquid Glass is reserved for navigation and control chrome.
//   * When hidden, we show dots (•) so the field's presence/length-feel is conveyed
//     without exposing the value.
//   * Content and inline actions share the opaque background at every contrast level.
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

@available(iOS 26.0, macOS 26.0, *)
public struct SecureRevealView: View {
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
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
        let layout = dynamicTypeSize.isAccessibilitySize
            ? AnyLayout(VStackLayout(alignment: .leading, spacing: Spacing.xs))
            : AnyLayout(HStackLayout(spacing: Spacing.md))
        layout {
            VStack(alignment: .leading, spacing: Spacing.xxs) {
                Text(title)
                    .font(Typography.caption)
                    .foregroundStyle(Palette.secondaryText)
                Text(displayString)
                    .font(isMonospaced ? Typography.secretValue : Typography.rowTitle)
                    .foregroundStyle(Palette.primaryText)
                    .textSelection(.enabled)
                    .privacySensitive(isRevealed)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(title)
            .accessibilityValue(isRevealed ? value : "已隐藏")

            HStack(spacing: Spacing.xs) {
                actionButton(isRevealed ? "隐藏\(title)" : "显示\(title)",
                             systemImage: isRevealed ? "eye.slash" : "eye") {
                    isRevealed.toggle()
                }
                if let onCopy {
                    actionButton("拷贝\(title)", systemImage: "doc.on.doc", action: onCopy)
                }
            }
        }
        .padding(.horizontal, Spacing.md)
        .padding(.vertical, Spacing.sm)
        .glassScrim(cornerRadius: CornerRadius.md)
    }

    private func actionButton(_ title: String, systemImage: String,
                              action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Label(title, systemImage: systemImage)
                .labelStyle(.iconOnly)
                #if os(iOS)
                .frame(minWidth: 44, minHeight: 44)
                #endif
                .contentShape(Rectangle())
        }
        .buttonStyle(.borderless)
        .help(title)
    }
}
