import SwiftUI
import DesignSystem
import UIShared
import VaultRepository

enum MacItemSort: String, CaseIterable {
    case name = "名称"
    case modified = "修改日期"
    case type = "类型"

    func title(locale: Locale) -> String { MacLocalization.text(rawValue, locale: locale) }

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
    let snapshotRevealed: Bool
    var onQuickCopy: ((String, MacQuickCopyField) -> Void)? = nil
    var copyReceipt: MacQuickCopyReceipt? = nil
    @Environment(\.locale) private var locale

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                if model.canShowMacSnapshot { Text("\(items.count) 个条目") }
                Spacer()
                if destination == .trash {
                    Button("清空回收站…", role: .destructive, action: onEmptyTrash)
                        .buttonStyle(.borderless)
                        .disabled(!hasTrash)
                } else {
                    Menu("按\(sort.title(locale: locale))") {
                        Picker("排序方式", selection: $sort) {
                            ForEach(MacItemSort.allCases, id: \.self) { order in
                                Text(order.title(locale: locale)).tag(order)
                            }
                        }
                    }
                    .menuStyle(.borderlessButton)
                    .fixedSize()
                    .accessibilityLabel("排序方式：\(sort.title(locale: locale))")
                }
            }
            .font(.subheadline)
            .foregroundStyle(.secondary)
            .padding(.horizontal, 16)
            .frame(minHeight: 30)

            List(items, id: \.macStableID, selection: $selection) { cipher in
                HStack(spacing: onQuickCopy == nil ? 10 : 6) {
                    HStack(spacing: 10) {
                        MacVaultItemBadge(cipher, diameter: 30)
                        VStack(alignment: .leading, spacing: Spacing.xxs) {
                            Text(cipher.name.nilIfBlank ?? MacLocalization.text("Untitled item", locale: locale)).font(.body.weight(.semibold))
                            Text(subtitle(for: cipher))
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                        }
                        .lineLimit(1)
                    }
                    .accessibilityElement(children: .combine)
                    .layoutPriority(onQuickCopy == nil ? 0 : 1)
                    Spacer(minLength: Spacing.xs)
                    if cipher.favorite {
                        Image(systemName: "star.fill").font(.caption)
                            .foregroundStyle(.orange).accessibilityLabel("已置顶")
                    }
                    if let id = cipher.id, let onQuickCopy {
                        HStack(spacing: 0) {
                            ForEach(MacQuickCopyField.allCases.filter { $0.isAvailable(in: cipher) }) { field in
                                quickCopyButton(field, id: id) { onQuickCopy(id, field) }
                            }
                        }
                    }
                }
                .privacySensitive()
                .frame(minHeight: 44)
                .listRowSeparator(.hidden)
                .tag(cipher.macStableID)
            }
            .listStyle(.inset)
            .macVaultSnapshotReveal(snapshotRevealed)
            .overlay { stateOverlay }
        }
    }

    private func quickCopyButton(_ field: MacQuickCopyField, id: String, action: @escaping () -> Void) -> some View {
        let copied = copyReceipt?.itemID == id && copyReceipt?.field == field
        return Button(action: action) {
            Image(systemName: copied ? "checkmark" : field.symbol)
                .font(.system(size: 12, weight: .medium))
                .frame(width: 28, height: 28)
                .contentShape(Rectangle())
        }
        .buttonStyle(.borderless)
        .help(Text(field.title))
        .accessibilityLabel(Text(field.title))
        .accessibilityValue("Copied", isEnabled: copied)
        .accessibilityIdentifier("mac.quick-copy.\(field.rawValue).\(id)")
    }

    private func subtitle(for cipher: PlaintextCipher) -> String {
        if destination == .trash, let date = cipher.deletedDate {
            return MacLocalization.format("%@ 移到回收站", MacLocalization.formattedDate(date, locale: locale), locale: locale)
        }
        if destination == .archive, let date = cipher.archivedDate {
            return MacLocalization.format("%@ 归档", MacLocalization.formattedDate(date, locale: locale), locale: locale)
        }
        return cipher.macSubtitle(in: locale) ?? cipher.macTypeLabel(in: locale)
    }

    @ViewBuilder private var stateOverlay: some View {
        if !model.canShowMacSnapshot {
            MacVaultReadStatus(model: model, onRetry: onRetry)
        } else if items.isEmpty {
            if isSearching {
                ContentUnavailableView("没有匹配的条目", systemImage: "magnifyingglass")
            } else {
                let title: LocalizedStringKey = switch destination {
                case .trash: "回收站是空的"
                case .archive: "没有归档的条目"
                case .folder: "这个文件夹还没有条目"
                case .favorites: "没有置顶的条目"
                case .unfiled: "没有未归类的条目"
                case .all: "没有条目"
                default: "没有\(MacLocalization.text(destination.titleKey, locale: locale))条目"
                }
                ContentUnavailableView(title, systemImage: destination.isHiddenCollection ? destination.systemImage : "tray")
            }
        }
    }
}

extension VaultListModel {
    var canShowMacSnapshot: Bool { hasLoadedContent && errorMessage == nil }
}

extension View {
    func macVaultSnapshotReveal(_ revealed: Bool) -> some View {
        modifier(MacVaultSnapshotReveal(revealed: revealed))
    }
}

private struct MacVaultSnapshotReveal: ViewModifier {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    let revealed: Bool

    func body(content: Content) -> some View {
        content.animation(reduceMotion ? nil : .easeOut(duration: 0.16)) { snapshot in
            snapshot.opacity(revealed ? 1 : 0)
        }
    }
}

struct MacVaultReadStatus: View {
    let model: VaultListModel
    let onRetry: () -> Void
    @Environment(\.locale) private var locale

    var body: some View {
        if let message = model.errorMessage {
            ContentUnavailableView {
                Label("无法载入保险库", systemImage: "exclamationmark.triangle")
            } description: {
                Text(MacLocalization.text(message, locale: locale))
            } actions: {
                Button("重试", action: onRetry).accessibilityIdentifier("mac.vault.retry")
            }
        } else {
            ProgressView("正在载入保险库…").controlSize(.small)
        }
    }
}
