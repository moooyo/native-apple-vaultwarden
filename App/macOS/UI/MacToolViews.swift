import SwiftUI
import UIShared
import DesignSystem

struct MacGeneratorView: View {
    @State private var model: GeneratorModel
    @State private var showsHistory = true

    init(model: GeneratorModel = GeneratorModel()) {
        _model = State(initialValue: model)
    }

    var body: some View {
        ScrollView {
            VStack(spacing: Spacing.lg) {
                GenerationModePicker(model: model)
                    .frame(maxWidth: 320)
                GenerationResultCard(model: model, centered: true)
                GenerationActions(model: model, copy: MacClipboard.copy)
                if let error = model.historyError {
                    Text(error).font(.footnote).foregroundStyle(.secondary)
                }
                GenerationOptions(model: model)
                    .padding(.top, Spacing.sm)
            }
            .frame(maxWidth: 560)
            .padding(Spacing.xl)
            .frame(maxWidth: .infinity)
        }
        .inspector(isPresented: $showsHistory) {
            VStack(alignment: .leading, spacing: 0) {
                HStack {
                    Text("生成历史").font(.headline).accessibilityAddTraits(.isHeader)
                    Spacer()
                    Button("清除", role: .destructive) { Task { await model.clearHistory() } }
                        .disabled(model.history.isEmpty || model.isHistoryBusy)
                }
                .padding(.horizontal, Spacing.lg)
                .padding(.vertical, Spacing.sm)
                GenerationHistoryList(model: model, copy: MacClipboard.copy)
            }
            .inspectorColumnWidth(min: 230, ideal: 300, max: 360)
        }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button(showsHistory ? "隐藏生成历史" : "显示生成历史", systemImage: "sidebar.right") {
                    showsHistory.toggle()
                }
            }
        }
        .task {
            await model.prepareHistory()
            if model.generated.isEmpty { model.regenerate() }
        }
    }
}

struct MacSendView: View {
    let vault: VaultService
    @Binding var showComposer: Bool
    var query = ""
    var onCountChange: ((Int) -> Void)?
    var dataRevision: UInt64 = 0

    var body: some View {
        SendWorkspace(service: vault.sendService, showComposer: $showComposer,
                      query: query, onCountChange: onCountChange, dataRevision: dataRevision)
    }
}
