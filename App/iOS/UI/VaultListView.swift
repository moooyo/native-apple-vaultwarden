import SwiftUI
import UIShared
import DesignSystem
import VaultRepository

@available(iOS 27.0, *)
public struct VaultListView: View {
    let model: VaultListModel
    let vault: VaultService
    let onAdd: () -> Void
    let onOpenSettings: () -> Void

    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    @State private var type: VaultWorkspaceSection = .all
    @State private var sort: VaultSortOrder = .name
    @State private var editingFolder: VaultFolderEditor?

    public init(model: VaultListModel, vault: VaultService,
                onAdd: @escaping () -> Void, onOpenSettings: @escaping () -> Void) {
        self.model = model
        self.vault = vault
        self.onAdd = onAdd
        self.onOpenSettings = onOpenSettings
    }

    public var body: some View {
        let visible = sort.sorted(model.items.filter { $0.isIncluded(in: type) })
        List {
            Section {
                VaultFilterChips(selection: $type, items: model.items)
                    .listRowInsets(EdgeInsets())
                    .listRowBackground(Color.clear)
            }
            if let message = model.errorMessage { VaultListError(message: message) }
            if type == .all {
                let favorites = sort.sorted(model.items.filter(\.favorite))
                if !favorites.isEmpty {
                    Section { pinnedGrid(favorites) } header: { VaultGroupHeading("置顶") }
                }
                Section {
                    ForEach(model.folders) { folder in
                        VaultFolderLink(id: folder.id, model: model, vault: vault)
                    }
                    VaultFolderLink(id: nil, model: model, vault: vault)
                } header: {
                    HStack {
                        VaultGroupHeading("文件夹")
                        Spacer()
                        Button { editingFolder = .create } label: {
                            Image(systemName: "plus.circle.fill")
                                .symbolRenderingMode(.hierarchical)
                                .font(.title2).frame(minWidth: 44, minHeight: 44)
                        }
                        .buttonStyle(.borderless)
                        .accessibilityLabel("新建文件夹")
                    }
                }
            }
            Section {
                if !visible.isEmpty {
                    VaultItemLinks(items: visible, model: model, vault: vault)
                } else if model.isLoading {
                    ProgressView().frame(maxWidth: .infinity)
                } else {
                    ContentUnavailableView(type == .all ? "保险库为空" : "没有此类型的条目",
                                           systemImage: "tray")
                }
            } header: {
                HStack(alignment: .firstTextBaseline) {
                    VaultGroupHeading(type.title)
                    Spacer()
                    Text("按\(sort.title)").font(.footnote).foregroundStyle(.secondary)
                }
                .textCase(nil)
            }
            Section {
                hiddenLink(.archive, count: model.archivedItems.count)
                hiddenLink(.trash, count: model.trashedItems.count)
            } header: { VaultGroupHeading("隐藏的条目") }
        }
        .listStyle(.insetGrouped)
        .environment(\.defaultMinListRowHeight, 52)
        .refreshable { await model.refresh() }
        .navigationTitle("保险库")
        .toolbarTitleDisplayMode(.inlineLarge)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button("设置", systemImage: "gearshape", action: onOpenSettings)
                    .accessibilityIdentifier("vault.settings")
            }
            ToolbarSpacer(.fixed, placement: .topBarTrailing)
            ToolbarItemGroup(placement: .topBarTrailing) {
                VaultSortMenu(selection: $sort)
                Button("新建条目", systemImage: "plus", action: onAdd)
            }
        }
        .vaultFolderDialogs(editor: $editingFolder, model: model, vault: vault)
    }

    private func pinnedGrid(_ favorites: [PlaintextCipher]) -> some View {
        let columns = Array(repeating: GridItem(.flexible(), spacing: Spacing.xs),
                            count: dynamicTypeSize.isAccessibilitySize ? 2 : 4)
        return LazyVGrid(columns: columns, spacing: Spacing.md) {
            ForEach(favorites, id: \.openVaultID) { cipher in
                NavigationLink {
                    ItemDetailView(model: ItemDetailModel(cipher: cipher), vault: vault) {
                        Task { await model.load() }
                    }
                } label: {
                    VStack(spacing: Spacing.sm) {
                        BrandBadge(cipher.openVaultName, diameter: 52)
                        Text(cipher.openVaultName)
                            .font(.footnote.weight(.medium))
                            .lineLimit(dynamicTypeSize.isAccessibilitySize ? nil : 2)
                            .multilineTextAlignment(.center)
                    }
                    .frame(maxWidth: .infinity, alignment: .top)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.borderless)
                .tint(.primary)
                .accessibilityIdentifier("vault.pinned.\(cipher.openVaultID)")
            }
        }
        .padding(.vertical, Spacing.xs)
        .listRowInsets(EdgeInsets(top: Spacing.sm, leading: Spacing.sm,
                                  bottom: Spacing.sm, trailing: Spacing.sm))
    }

    private func hiddenLink(_ section: VaultHiddenSection, count: Int) -> some View {
        NavigationLink {
            VaultHiddenView(model: model, vault: vault, initialSection: section)
        } label: {
            HStack {
                Label(section.title, systemImage: section.systemImage)
                Spacer()
                Text(count, format: .number).foregroundStyle(.secondary).monospacedDigit()
            }
        }
        .accessibilityIdentifier("vault.\(section.rawValue)")
    }
}

@available(iOS 27.0, *)
struct VaultSearchView: View {
    let model: VaultListModel
    let vault: VaultService
    @Environment(\.horizontalSizeClass) private var sizeClass
    @State private var type: VaultWorkspaceSection = .all

    var body: some View {
        let results = VaultSortOrder.name.sorted(model.items.filter { $0.isIncluded(in: type) })
        List {
            Section {
                VaultFilterChips(selection: $type, items: model.items, wraps: true, search: true)
                    .listRowInsets(EdgeInsets())
                    .listRowBackground(Color.clear)
            } header: { VaultGroupHeading("按类型查找") }
            if let message = model.errorMessage { VaultListError(message: message) }
            Section {
                if !results.isEmpty {
                    VaultItemLinks(items: results, model: model, vault: vault)
                } else if model.isLoading {
                    ProgressView().frame(maxWidth: .infinity)
                } else {
                    ContentUnavailableView("没有结果", systemImage: "magnifyingglass",
                                           description: Text(emptyDescription))
                }
            } header: {
                VaultGroupHeading(model.query.isEmpty && type == .all ? "全部条目" : "\(results.count) 个结果")
            }
        }
        .listStyle(.insetGrouped)
        .frame(maxWidth: sizeClass == .regular ? LayoutMetric.padSearchWidth : .infinity)
        .frame(maxWidth: .infinity)
        .background(Palette.groupedBackground)
        .navigationTitle("搜索")
        .navigationBarTitleDisplayMode(sizeClass == .regular ? .large : .inline)
    }

    private var emptyDescription: String {
        if !model.query.isEmpty { return "没有条目的名称、用户名或网站包含“\(model.query)”。" }
        return type == .all ? "保险库中还没有条目。" : "此类型没有匹配的条目。"
    }
}

@available(iOS 27.0, *)
struct VaultItemLinks: View {
    let items: [PlaintextCipher]
    let model: VaultListModel
    let vault: VaultService
    @Environment(\.vaultFeedback) private var feedback
    @State private var operationError: String?

    var body: some View {
        ForEach(items, id: \.openVaultID) { cipher in
            NavigationLink {
                ItemDetailView(model: ItemDetailModel(cipher: cipher), vault: vault) {
                    Task { await model.reloadCurrentView() }
                }
            } label: {
                VaultItemRow(cipher: cipher, showsFavorite: false, showsDisclosureIndicator: false)
            }
            .listRowInsets(EdgeInsets(top: 0, leading: Spacing.lg, bottom: 0, trailing: Spacing.lg))
            .accessibilityIdentifier("vault.item.\(cipher.openVaultID)")
            .swipeActions(edge: .trailing, allowsFullSwipe: false) { actions(for: cipher) }
            .contextMenu { actions(for: cipher) }
        }
        .alert("无法更改条目", isPresented: Binding(get: { operationError != nil },
                                              set: { if !$0 { operationError = nil } })) {
            Button("好", role: .cancel) {}
        } message: { Text(operationError ?? "请刷新保险库后重试。") }
    }

    @ViewBuilder private func actions(for cipher: PlaintextCipher) -> some View {
        if let id = cipher.id {
            Button(role: .destructive) { move(id: id, to: .trash) } label: {
                Label("移到回收站", systemImage: "trash")
            }
            .accessibilityIdentifier("vault.trash.\(id)")
            Button { move(id: id, to: .archive) } label: {
                Label("归档", systemImage: "archivebox")
            }
            .tint(.orange)
        }
    }

    private func move(id: String, to section: VaultHiddenSection) {
        Task {
            do {
                if section == .trash { try await vault.trashCipher(id: id) }
                else { try await vault.archiveCipher(id: id) }
                feedback?.show(section == .trash ? "已移到回收站" : "已归档") {
                    if section == .trash { try await vault.restoreCipher(id: id) }
                    else { try await vault.unarchiveCipher(id: id) }
                    await model.reloadCurrentView()
                }
                await model.reloadCurrentView()
            } catch { operationError = "操作未完成，请刷新保险库后重试。" }
        }
    }
}

struct VaultGroupHeading: View {
    let title: String
    init(_ title: String) { self.title = title }

    var body: some View {
        Text(title)
            .font(.title3.weight(.semibold))
            .foregroundStyle(.primary)
            .textCase(nil)
            .accessibilityAddTraits(.isHeader)
    }
}

struct VaultListError: View {
    let message: String

    var body: some View {
        Label(message, systemImage: "exclamationmark.triangle")
            .font(.subheadline).foregroundStyle(.red)
    }
}
