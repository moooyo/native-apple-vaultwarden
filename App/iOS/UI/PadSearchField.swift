import SwiftUI
import DesignSystem

@available(iOS 27.0, *)
struct PadSearchField: View {
    @Binding var text: String
    let onClose: () -> Void
    @FocusState private var focused: Bool

    var body: some View {
        HStack(spacing: Spacing.sm) {
            HStack(spacing: Spacing.sm) {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(.secondary)
                    .accessibilityHidden(true)
                TextField("搜索保险库", text: $text)
                    .focused($focused)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .submitLabel(.search)
                    .accessibilityIdentifier("search.field")
                if !text.isEmpty {
                    Button("清除搜索", systemImage: "xmark.circle.fill") {
                        text = ""
                        focused = true
                    }
                    .labelStyle(.iconOnly)
                    .foregroundStyle(.secondary)
                    .frame(minWidth: LayoutMetric.minimumTapTarget, minHeight: LayoutMetric.minimumTapTarget)
                }
            }
            .padding(.leading, Spacing.lg)
            .padding(.trailing, Spacing.xs)
            .frame(minHeight: LayoutMetric.minimumTapTarget)
            .glassStyle(in: Capsule())
            Button("关闭搜索", systemImage: "xmark", action: onClose)
                .labelStyle(.iconOnly)
                .buttonStyle(.glass)
                .buttonBorderShape(.circle)
                .controlSize(.large)
                .keyboardShortcut(.cancelAction)
                .accessibilityIdentifier("search.close")
        }
        .frame(maxWidth: 560)
        .padding(.horizontal, Spacing.lg)
        .padding(.bottom, Spacing.sm)
        .onAppear { focused = true }
    }
}
