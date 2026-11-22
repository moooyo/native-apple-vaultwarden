import SwiftUI
import DesignSystem
import VaultRepository

enum MacItemSort: String, CaseIterable {
    case name = "名称"
    case modified = "修改日期"
    case type = "类型"

    func precedes(_ first: PlaintextCipher, _ second: PlaintextCipher) -> Bool {
        switch self {
        case .modified where first.revisionDate != second.revisionDate:
            return (first.revisionDate ?? .distantPast) > (second.revisionDate ?? .distantPast)
        case .type where first.macTypeLabel != second.macTypeLabel:
            return first.macTypeLabel.localizedStandardCompare(second.macTypeLabel) == .orderedAscending
        default:
            let comparison = first.name.localizedStandardCompare(second.name)
            return comparison == .orderedSame ? first.macStableID < second.macStableID : comparison == .orderedAscending
        }
    }
}

struct MacItemListView: View {
    let items: [PlaintextCipher]
    let isLoading: Bool
    let errorMessage: String?
    let isSearching: Bool
    let destination: MacDestination
    @Binding var selection: String?
    @Binding var sort: MacItemSort
    let onEmptyTrash: () -> Void
    let hasTrash: Bool

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("\(items.count) 个条目")
                Spacer()
                if destination == .trash {
                    Button("清空回收站…", role: .destructive, action: onEmptyTrash)
                        .buttonStyle(.borderless)
                        .disabled(!hasTrash)
                } else {
                    Menu("按\(sort.rawValue)") {
                        Picker("排序方式", selection: $sort) {
                            ForEach(MacItemSort.allCases, id: \.self) { order in
                                Text(order.rawValue).tag(order)
                            }
                        }
                    }
                    .menuStyle(.borderlessButton)
                    .fixedSize()
                    .accessibilityLabel("排序方式：\(sort.rawValue)")
                }
            }
            .font(.subheadline)
            .foregroundStyle(.secondary)
            .padding(.horizontal, 16)
            .frame(minHeight: 30)

            List(items, id: \.macStableID, selection: $selection) { cipher in
                HStack(spacing: 10) {
                    BrandBadge(cipher.name, diameter: 30)
                    VStack(alignment: .leading, spacing: Spacing.xxs) {
                        Text(cipher.name.nilIfBlank ?? "未命名条目").font(.body.weight(.semibold))
                        Text(cipher.macSubtitle ?? cipher.macTypeLabel)
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                    .lineLimit(1)
                    Spacer(minLength: Spacing.xs)
                    if cipher.favorite {
                        Image(systemName: "star.fill").font(.caption)
                            .foregroundStyle(.orange).accessibilityLabel("已置顶")
                    }
                }
                .privacySensitive()
                .frame(minHeight: 44)
                .accessibilityElement(children: .combine)
                .tag(cipher.macStableID)
            }
            .listStyle(.inset)
            .overlay { stateOverlay }
        }
    }

    @ViewBuilder private var stateOverlay: some View {
        if items.isEmpty {
            if isLoading {
                ProgressView("正在载入保险库…").controlSize(.small)
            } else if let errorMessage {
                ContentUnavailableView("无法载入保险库", systemImage: "exclamationmark.triangle", description: Text(errorMessage))
            } else if isSearching {
                ContentUnavailableView("没有匹配的条目", systemImage: "magnifyingglass")
            } else {
                let title = destination == .trash ? "回收站是空的" : destination == .archive ? "没有归档的条目" : "没有条目"
                ContentUnavailableView(title, systemImage: destination.isHiddenCollection ? destination.systemImage : "tray")
            }
        }
    }
}
