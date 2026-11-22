import SwiftUI
import DesignSystem
import UIShared
import VaultRepository

@available(iOS 27.0, *)
enum PadVaultScope: Hashable {
    case all, type(VaultWorkspaceSection), folder(String?), archive, trash
}

@available(iOS 27.0, *)
struct PadVaultColumns: View {
    let model: VaultListModel
    let vault: VaultService
    let scope: PadVaultScope
    let isActive: Bool
    @Binding var selectedID: String?
    @Binding var sort: VaultSortOrder
    let onAdd: (String?) -> Void
    let onSettings: () -> Void
    let onSelectScope: (VaultWorkspaceSection) -> Void
    let onSidebarChange: (Bool) -> Void
    @Environment(\.tabBarPlacement) private var tabBarPlacement
    @State private var visibility = NavigationSplitViewVisibility.all

    private var sidebarVisible: Bool { tabBarPlacement == .sidebar }

    private var folderID: String? {
        if case let .folder(id) = scope { return id }
        return nil
    }

    private var title: String {
        switch scope {
        case .all: "保险库"
        case let .type(type): type.title
        case let .folder(id?): model.folders.first(where: { $0.id == id })?.name ?? "文件夹"
        case .folder(nil): "无文件夹"
        case .archive: "归档"
        case .trash: "回收站"
        }
    }

    private var items: [PlaintextCipher] {
        switch scope {
        case .all: sort.sorted(model.items)
        case let .type(section): sort.sorted(model.items.filter { $0.isIncluded(in: section) })
        case let .folder(id): sort.sorted(model.items.filter { $0.folderID == id })
        case .archive: sort.sorted(model.archivedItems)
        case .trash: sort.sorted(model.trashedItems)
        }
    }

    private var chipSelection: Binding<VaultWorkspaceSection> {
        Binding(get: { if case let .type(section) = scope { section } else { .all } }, set: onSelectScope)
    }

    var body: some View {
        let visible = items
        NavigationSplitView(columnVisibility: $visibility) {
            List(selection: $selectedID) {
                if !sidebarVisible {
                    VaultFilterChips(selection: chipSelection, items: model.items, wraps: true)
                        .listRowSeparator(.hidden)
                        .selectionDisabled()
                }
                if let error = model.errorMessage { VaultListError(message: error).selectionDisabled() }
                ForEach(visible, id: \.openVaultID) { cipher in
                    NavigationLink(value: cipher.openVaultID) {
                        VaultItemRow(cipher: cipher, showsDisclosureIndicator: false)
                            .frame(minHeight: LayoutMetric.padRowHeight)
                    }
                    .accessibilityIdentifier("pad.item.\(cipher.openVaultID)")
                }
                if visible.isEmpty, model.errorMessage == nil {
                    emptyList
                        .frame(maxWidth: .infinity)
                        .listRowSeparator(.hidden)
                        .selectionDisabled()
                }
            }
            .listStyle(.plain)
            .refreshable { await model.refresh() }
            .navigationTitle(title)
            .navigationBarTitleDisplayMode(.large)
            .navigationSplitViewColumnWidth(min: 275, ideal: sidebarVisible ? LayoutMetric.padListWidthWithSidebar : LayoutMetric.padListWidth, max: 420)
            .toolbar {
                ToolbarItemGroup(placement: .topBarTrailing) {
                    if !sidebarVisible {
                        Button("设置", systemImage: "gearshape", action: onSettings)
                            .accessibilityIdentifier("navigation.settings")
                    }
                    VaultSortMenu(selection: $sort)
                    if scope != .archive, scope != .trash {
                        Button("新建条目", systemImage: "plus") { onAdd(folderID) }
                    }
                }
            }
        } detail: {
            if let cipher = visible.first(where: { $0.openVaultID == selectedID }) {
                ItemDetailView(model: ItemDetailModel(cipher: cipher), vault: vault, isSplitDetail: true,
                               onSelectClone: { selectedID = $0 }) {
                    Task { await model.load() }
                }
                .id(cipher.openVaultID)
            } else {
                ContentUnavailableView("选择一个条目", systemImage: "rectangle.split.2x1")
            }
        }
        .navigationSplitViewStyle(.balanced)
        .onChange(of: tabBarPlacement) { _, placement in
            if let placement { onSidebarChange(placement == .sidebar) }
        }
        .onChange(of: visible.map(\.openVaultID), initial: true) { _, ids in
            if isActive, selectedID.map({ ids.contains($0) }) != true { selectedID = ids.first }
        }
        .onChange(of: isActive) { _, active in
            if active, !visible.contains(where: { $0.openVaultID == selectedID }) { selectedID = visible.first?.openVaultID }
        }
    }

    @ViewBuilder private var emptyList: some View {
        if model.isLoading {
            ProgressView()
        } else {
            switch scope {
            case .archive: ContentUnavailableView("没有归档的条目", systemImage: "archivebox")
            case .trash: ContentUnavailableView("回收站是空的", systemImage: "trash")
            case .folder: ContentUnavailableView("此文件夹为空", systemImage: "folder")
            default: ContentUnavailableView("没有条目", systemImage: "tray")
            }
        }
    }
}
