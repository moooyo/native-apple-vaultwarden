import SwiftUI
import UIShared
import DesignSystem

@available(iOS 27.0, *)
public struct GeneratorView: View {
    @Environment(\.horizontalSizeClass) private var sizeClass
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    @State private var model: GeneratorModel
    @State private var showsHistory = false

    public init(model: GeneratorModel = GeneratorModel()) {
        _model = State(initialValue: model)
    }

    public var body: some View {
        GeometryReader { geometry in
            let wide = sizeClass == .regular && geometry.size.width >= 680 && !dynamicTypeSize.isAccessibilitySize
            ScrollView {
                if wide {
                    HStack(alignment: .top, spacing: 28) {
                        result(wide: true)
                        options(wide: true)
                    }
                    .padding(.horizontal, 28)
                    .frame(maxWidth: 1040)
                    .frame(maxWidth: .infinity)
                } else {
                    VStack(alignment: .leading, spacing: Spacing.xl) {
                        result(wide: false)
                        options(wide: false)
                    }
                    .padding(.horizontal, Spacing.lg)
                }
            }
            .contentMargins(.vertical, Spacing.md, for: .scrollContent)
        }
        .background(Palette.groupedBackground)
        .navigationTitle("生成器")
        .toolbarTitleDisplayMode(sizeClass == .regular ? .large : .inlineLarge)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button("生成历史", systemImage: "clock.arrow.circlepath") { showsHistory = true }
                    .popover(isPresented: $showsHistory) {
                        historyPresentation
                            .presentationCompactAdaptation(.sheet)
                    }
            }
        }
        .task {
            await model.prepareHistory()
            if model.generated.isEmpty { model.regenerate() }
        }
    }

    private func result(wide: Bool) -> some View {
        VStack(spacing: Spacing.lg) {
            GenerationModePicker(model: model)
            GenerationResultCard(model: model, wide: wide)
            GenerationActions(model: model, copy: Clipboard.copy)
            if let error = model.historyError {
                Text(error).font(.footnote).foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity)
    }

    private func options(wide: Bool) -> some View {
        VStack(alignment: .leading, spacing: Spacing.sm) {
            Text("选项")
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(.secondary)
                .padding(.horizontal, Spacing.lg)
                .accessibilityAddTraits(.isHeader)
            GenerationOptions(model: model, wide: wide)
        }
        .frame(maxWidth: .infinity)
    }

    private var historyPresentation: some View {
        NavigationStack {
            GenerationHistoryList(model: model, copy: Clipboard.copy)
                .navigationTitle("生成历史")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("清除", role: .destructive) { Task { await model.clearHistory() } }
                            .disabled(model.history.isEmpty || model.isHistoryBusy)
                    }
                    ToolbarItem(placement: .confirmationAction) {
                        Button("完成", systemImage: "checkmark") { showsHistory = false }
                    }
                }
        }
        .frame(idealWidth: sizeClass == .regular ? 400 : nil,
               idealHeight: sizeClass == .regular ? 350 : nil)
        .presentationDragIndicator(.visible)
    }
}
