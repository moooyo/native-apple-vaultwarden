import SwiftUI
import UIShared
import VaultRepository
import DesignSystem

enum VaultHiddenSection: String, CaseIterable {
    case trash, archive

    var title: String { self == .trash ? "回收站" : "归档" }
    var systemImage: String { self == .trash ? "trash" : "archivebox" }
}

struct VaultTrashRemoval {
    let ids: [String]
    let title: String
}

@available(iOS 27.0, *)
struct VaultHiddenView: View {
    let model: VaultListModel
    let vault: VaultService
    let initialSection: VaultHiddenSection
    @Environment(\.vaultFeedback) private var feedback
    @State private var permanentDeletion: VaultTrashRemoval?
    @State private var errorMessage: String?
    @State private var busy = false

    var body: some View {
        List {
            if !model.canPresentCounts { VaultReadStatus(model: model) }
            if model.hasLoadedContent {
                ForEach([initialSection, initialSection == .trash ? .archive : .trash], id: \.self) { section in
                    let items = section == .trash ? model.trashedItems : model.archivedItems
                    Section {
                        if items.isEmpty, model.canPresentCounts {
                            Text(section == .trash ? "回收站是空的" : "没有归档的条目")
                                .foregroundStyle(.secondary).frame(minHeight: 44)
                        }
                        ForEach(items, id: \.openVaultID) { item in row(item, in: section) }
                    } header: {
                        if section != initialSection { VaultGroupHeading(section.title) }
                    }
                }
            }
        }
        .listStyle(.insetGrouped)
        .contentMargins(.horizontal, Spacing.lg, for: .scrollContent)
        .navigationTitle(initialSection.title)
        .navigationBarTitleDisplayMode(.large)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                EmptyTrashButton(model: model, vault: vault, pending: $permanentDeletion, busy: $busy)
            }
        }
        .refreshable { await model.refresh() }
        .alert("操作未完成", isPresented: Binding(get: { errorMessage != nil },
                                            set: { if !$0 { errorMessage = nil } })) {
            Button("好", role: .cancel) {}
        } message: { Text(errorMessage ?? "请刷新保险库后重试。") }
    }

    private func row(_ item: PlaintextCipher, in section: VaultHiddenSection) -> some View {
        HStack(spacing: Spacing.sm) {
            VaultItemRow(cipher: item, showsFavorite: false, showsDisclosureIndicator: false,
                         subtitleOverride: subtitle(for: item, in: section), wrapsSubtitle: section == .archive)
            if section == .archive, let id = item.id {
                Button("取消归档") { restore(id: id, from: section) }
                    .buttonStyle(.bordered)
                    .accessibilityLabel("取消归档“\(item.openVaultName)”")
            }
        }
        .listRowInsets(EdgeInsets(top: 0, leading: Spacing.lg, bottom: 0, trailing: Spacing.lg))
        .contentShape(Rectangle())
        .accessibilityElement(children: section == .trash ? .combine : .contain)
        .accessibilityIdentifier("\(section.rawValue).item.\(item.openVaultID)")
        .swipeActions(edge: .trailing, allowsFullSwipe: false) { actions(for: item, in: section) }
        .contextMenu { actions(for: item, in: section, removalRole: .destructive) }
        .disabled(busy)
    }

    @ViewBuilder private func actions(for item: PlaintextCipher, in section: VaultHiddenSection,
                                      removalRole: ButtonRole? = nil) -> some View {
        if let id = item.id {
            if section == .trash {
                Button(role: removalRole) {
                    permanentDeletion = VaultTrashRemoval(ids: [id], title: "永久删除“\(item.openVaultName)”？")
                } label: { Label("删除", systemImage: "trash") }
                .tint(.red)
                .accessibilityIdentifier("trash.delete.\(id)")
            }
            Button { restore(id: id, from: section) } label: {
                Label(section == .trash ? "恢复" : "取消归档", systemImage: "arrow.uturn.backward")
            }
            .tint(.blue)
            .accessibilityIdentifier("\(section.rawValue).restore.\(id)")
        }
    }

    private func subtitle(for item: PlaintextCipher, in section: VaultHiddenSection) -> String {
        let date = section == .trash ? item.deletedDate : item.archivedDate
        let folder = model.folders.first { $0.id == item.folderID }?.name ?? "无文件夹"
        guard let date else { return folder }
        let event = section == .trash ? "删除" : "归档"
        return "\(date.formatted(date: .abbreviated, time: .omitted))\(event) · \(folder)"
    }

    private func restore(id: String, from section: VaultHiddenSection) {
        guard !busy else { return }
        busy = true
        Task {
            defer { busy = false }
            do {
                if section == .trash { try await vault.restoreCipher(id: id) }
                else { try await vault.unarchiveCipher(id: id) }
                await model.load()
                feedback?.show(section == .trash ? "已恢复条目" : "已取消归档")
            } catch { errorMessage = "未能恢复此条目，请刷新保险库后重试。" }
        }
    }

}

@available(iOS 27.0, *)
struct EmptyTrashButton: View {
    let model: VaultListModel
    let vault: VaultService
    @Binding var pending: VaultTrashRemoval?
    @Binding var busy: Bool
    @Environment(\.vaultFeedback) private var feedback
    @State private var errorMessage: String?

    var body: some View {
        Button("清空") {
            let ids = model.trashedItems.compactMap(\.id)
            pending = VaultTrashRemoval(ids: ids, title: "永久删除回收站中的 \(ids.count) 个条目？")
        }
        .accessibilityLabel("清空回收站")
        .accessibilityIdentifier("trash.empty")
        .disabled(!model.canPresentCounts || model.trashedItems.isEmpty || busy)
        .confirmationDialog(pending?.title ?? "永久删除？", isPresented: Binding(get: { pending != nil },
                             set: { if !$0 { pending = nil } }), titleVisibility: .visible, presenting: pending) { removal in
            Button("永久删除", role: .destructive) { remove(removal) }
            Button("取消", role: .cancel) {}
        } message: { _ in Text(TrashRemovalBatch.confirmationMessage) }
        .alert("操作未完成", isPresented: Binding(get: { errorMessage != nil }, set: { if !$0 { errorMessage = nil } })) {
            Button("好", role: .cancel) {}
        } message: { Text(errorMessage ?? "") }
    }

    private func remove(_ removal: VaultTrashRemoval) {
        guard !busy, !removal.ids.isEmpty else { return }
        busy = true
        Task {
            defer { busy = false }
            do {
                let count = try await TrashRemovalBatch(ids: removal.ids).perform {
                    try await vault.permanentlyDeleteCipher(id: $0)
                }
                feedback?.show(TrashRemovalBatch.receipt(for: count))
            } catch let failure as TrashRemovalBatch.Failure {
                errorMessage = failure.message
            } catch is CancellationError { return } catch {
                errorMessage = "未能完成删除，请同步保险库后核对结果。"
            }
            await model.load()
        }
    }
}
