import SwiftUI
import DesignSystem
import UIShared
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
    let model: VaultListModel
    let isSearching: Bool
    let destination: MacDestination
    @Binding var selection: String?
    @Binding var sort: MacItemSort
    let onRetry: () -> Void
    let onEmptyTrash: () -> Void
    let hasTrash: Bool

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                if model.canPresentCounts { Text("\(items.count) 个条目") }
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
                    BrandBadge(cipher, diameter: 30)
                    VStack(alignment: .leading, spacing: Spacing.xxs) {
                        Text(cipher.name.nilIfBlank ?? "未命名条目").font(.body.weight(.semibold))
                        Text(subtitle(for: cipher))
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
                .listRowSeparator(.hidden)
                .tag(cipher.macStableID)
            }
            .listStyle(.inset)
            .overlay { stateOverlay }
        }
    }

    private func subtitle(for cipher: PlaintextCipher) -> String {
        if destination == .trash, let date = cipher.deletedDate {
            return "\(date.formatted(date: .abbreviated, time: .omitted)) 移到回收站"
        }
        if destination == .archive, let date = cipher.archivedDate {
            return "\(date.formatted(date: .abbreviated, time: .omitted)) 归档"
        }
        return cipher.macSubtitle ?? cipher.macTypeLabel
    }

    @ViewBuilder private var stateOverlay: some View {
        if !model.canPresentCounts {
            MacVaultReadStatus(model: model, onRetry: onRetry)
        } else if items.isEmpty {
            if isSearching {
                ContentUnavailableView("没有匹配的条目", systemImage: "magnifyingglass")
            } else {
                let title = switch destination {
                case .trash: "回收站是空的"
                case .archive: "没有归档的条目"
                case .folder: "这个文件夹还没有条目"
                case .favorites: "没有置顶的条目"
                case .unfiled: "没有未归类的条目"
                case .all: "没有条目"
                default: "没有\(destination.title)条目"
                }
                ContentUnavailableView(title, systemImage: destination.isHiddenCollection ? destination.systemImage : "tray")
            }
        }
    }
}

struct MacVaultReadStatus: View {
    let model: VaultListModel
    let onRetry: () -> Void

    var body: some View {
        if let message = model.errorMessage {
            ContentUnavailableView {
                Label("无法载入保险库", systemImage: "exclamationmark.triangle")
            } description: {
                Text(message)
            } actions: {
                Button("重试", action: onRetry).accessibilityIdentifier("mac.vault.retry")
            }
        } else {
            ProgressView("正在载入保险库…").controlSize(.small)
        }
    }
}
