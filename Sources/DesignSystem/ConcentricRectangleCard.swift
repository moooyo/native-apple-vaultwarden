import SwiftUI

// MARK: - ConcentricRectangleCard
//
// A card container for list rows / detail cards. Liquid Glass intent:
//
//   * The card's *content layer stays OPAQUE* — per Apple's guidance, glass lives in
//     the navigation/control chrome, not under content. So the fill here is a solid
//     `Palette.contentBackground`, never a glass material. The "Liquid Glass" tie-in
//     is the SHAPE: we use `ConcentricRectangle`, which adapts its corner radii to the
//     container it sits in so nested rows/cards stay visually concentric with the
//     enclosing sheet/window corners (the modern replacement for a fixed
//     `RoundedRectangle`).
//   * Fallback: on platforms/SDKs without `ConcentricRectangle` we degrade to a
//     `RoundedRectangle` with `CornerRadius.card`. On this SDK `ConcentricRectangle`
//     is available, so it is used directly.
//
// Accessibility: because the content layer is opaque, no transparency fallback is
// needed for the card itself; any glass chrome around it is handled by `GlassScrim` /
// standard controls.

@available(iOS 26.0, macOS 26.0, *)
public struct ConcentricRectangleCard<Content: View>: View {
    private let cornerRadius: CGFloat
    private let padding: CGFloat
    private let content: Content

    /// - Parameters:
    ///   - cornerRadius: corner radius used by the fallback shape and as the
    ///     `ConcentricRectangle`'s minimum. Defaults to `CornerRadius.card`.
    ///   - padding: inner padding around `content`.
    ///   - content: the (opaque) card content.
    public init(
        cornerRadius: CGFloat = CornerRadius.card,
        padding: CGFloat = Spacing.lg,
        @ViewBuilder content: () -> Content
    ) {
        self.cornerRadius = cornerRadius
        self.padding = padding
        self.content = content()
    }

    public var body: some View {
        content
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background {
                // Opaque content layer. `ConcentricRectangle` keeps the corners in
                // step with the enclosing container; we set a `minimum` fixed radius so
                // a top-level card (no rounded container) still reads as a card.
                ConcentricRectangle(corners: .concentric(minimum: .fixed(cornerRadius)), isUniform: true)
                    .fill(Palette.contentBackground)
            }
            .contentShape(Rectangle())
    }
}
