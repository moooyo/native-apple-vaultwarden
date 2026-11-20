import SwiftUI
import DesignSystem
import VaultRepository

@available(macOS 27.0, *)
struct MacItemListView: View {
    enum SortOrder: String, CaseIterable {
        case name = "名称"
        case favorite = "置顶优先"
    }

    let title: String
    let items: [PlaintextCipher]
    let isLoading: Bool
    let errorMessage: String?
    @Binding var selection: String?
    let onNewItem: () -> Void

    @State private var sortOrder: SortOrder = .name

    private var sortedItems: [PlaintextCipher] {
        items.sorted { lhs, rhs in
            if sortOrder == .favorite, lhs.favorite != rhs.favorite { return lhs.favorite }
            return lhs.name.localizedStandardCompare(rhs.name) == .orderedAscending
        }
    }

    var body: some View {
        List(selection: $selection) {
            ForEach(sortedItems, id: \.macStableID) { cipher in
                HStack(spacing: 10) {
                    BrandBadge(cipher.name, diameter: 30)
                    VStack(alignment: .leading, spacing: Spacing.xxs) {
                        Text(cipher.name.nilIfBlank ?? "未命名条目")
                            .font(.headline)
                        if let subtitle = cipher.macSubtitle {
                            Text(subtitle)
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .lineLimit(1)
                    Spacer(minLength: Spacing.xs)
                    if cipher.favorite {
                        Image(systemName: "star.fill")
                            .font(.caption)
                            .accessibilityLabel("已置顶")
                    }
                }
                .frame(minHeight: 40)
                .accessibilityElement(children: .combine)
                .tag(cipher.macStableID)
            }
        }
        .listStyle(.inset)
        .navigationTitle(title)
        .overlay { stateOverlay }
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                Menu {
                    Picker("排序", selection: $sortOrder) {
                        ForEach(SortOrder.allCases, id: \.self) { order in
                            Text(order.rawValue).tag(order)
                        }
                    }
                } label: {
                    Label("排序", systemImage: "arrow.up.arrow.down")
                }
                .help("排序条目")

                Button("新建条目", systemImage: "plus", action: onNewItem)
                    .help("新建条目")
            }
        }
    }

    @ViewBuilder
    private var stateOverlay: some View {
        if isLoading && items.isEmpty {
            ProgressView("正在载入保险库…")
                .controlSize(.small)
        } else if let errorMessage, items.isEmpty {
            ContentUnavailableView("无法载入保险库", systemImage: "exclamationmark.triangle",
                                   description: Text(errorMessage))
        } else if items.isEmpty {
            ContentUnavailableView("没有条目", systemImage: "tray",
                                   description: Text("此分类中暂时没有内容。"))
        }
    }
}
