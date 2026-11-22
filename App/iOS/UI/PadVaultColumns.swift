import SwiftUI
import DesignSystem
import UIShared
import VaultModels
import VaultRepository

@available(iOS 27.0, *)
enum PadVaultScope: Hashable {
    case all, type(VaultWorkspaceSection), folder(String?), archive, trash

    var creationType: CipherType {
        switch self {
        case .type(.cards): .card
        case .type(.identities): .identity
        case .type(.secureNotes): .secureNote
        case .type(.sshKeys): .sshKey
        default: .login
        }
    }

    var creationFolderID: String? {
        if case let .folder(id) = self { return id }
        return nil
    }

    func includes(_ cipher: PlaintextCipher) -> Bool {
        switch self {
        case .all: true
        case let .type(section): cipher.isIncluded(in: section)
        case let .folder(id): cipher.folderID == id
        case .archive, .trash: false
        }
    }
}

@available(iOS 27.0, *)
struct PadVaultColumns: View {
    let model: VaultListModel
    let vault: VaultService
    let scope: PadVaultScope
    let isActive: Bool
    @Binding var selectedID: String?
    @Binding var sort: VaultSortOrder
    let onAdd: () -> Void
    let onClone: (String) -> Void
    let onSettings: () -> Void
    let onSelectScope: (VaultWorkspaceSection) -> Void
    let onSidebarChange: (Bool) -> Void
    @Environment(\.vaultSyncModel) private var syncModel
    @Environment(\.tabBarPlacement) private var tabBarPlacement
    @Environment(\.colorSchemeContrast) private var contrast
    @Environment(\.accessibilityDifferentiateWithoutColor) private var differentiateWithoutColor
    @State private var visibility = NavigationSplitViewVisibility.all
    @State private var permanentDeletion: VaultTrashRemoval?
    @State private var emptyingTrash = false
    @State private var pendingCloneID: String?

    private var sidebarVisible: Bool { tabBarPlacement == .sidebar }

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
        let scopedItems: [PlaintextCipher] = switch scope {
        case .all: model.items
        case .type, .folder: model.items.filter(scope.includes)
        case .archive: model.archivedItems
        case .trash: model.trashedItems
        }
        return sort.sorted(scopedItems.filter(\.favorite)) + sort.sorted(scopedItems.filter { !$0.favorite })
    }

    private var chipSelection: Binding<VaultWorkspaceSection> {
        Binding(get: { if case let .type(section) = scope { section } else { .all } }, set: { onSelectScope($0) })
    }

    var body: some View {
        let visible = items
        NavigationSplitView(columnVisibility: $visibility) {
            List(selection: $selectedID) {
                Text(title)
                    .font(.title.bold())
                    .foregroundStyle(Palette.primaryText)
                    .accessibilityAddTraits(.isHeader)
                    .listRowInsets(EdgeInsets(top: Spacing.sm, leading: Spacing.lg, bottom: Spacing.sm, trailing: Spacing.lg))
                    .listRowSeparator(.hidden)
                    .selectionDisabled()
                if let syncModel, syncModel.hasOutstandingChanges || syncModel.errorMessage != nil || syncModel.isOutboxStatusUnavailable {
                    SyncAttentionButton(model: syncModel, onOpenSettings: onSettings)
                        .selectionDisabled()
                }
                if !sidebarVisible, model.canPresentCounts {
                    VaultFilterChips(selection: chipSelection, items: model.items, wraps: true)
                        .listRowSeparator(.hidden)
                        .selectionDisabled()
                }
                if !model.canPresentCounts {
                    VaultReadStatus(model: model).selectionDisabled()
                }
                ForEach(visible, id: \.openVaultID) { cipher in
                    let selected = selectedID == cipher.openVaultID
                    NavigationLink(value: cipher.openVaultID) {
                        VaultItemRow(cipher: cipher, badgeSize: 38, showsDisclosureIndicator: false, isListSelection: selected)
                            .padding(.horizontal, Spacing.md)
                            .frame(maxWidth: .infinity, minHeight: LayoutMetric.padRowHeight, alignment: .leading)
                            .background { if selected { selectedRowBackground } }
                            .contentShape(.rect)
                    }
                    .accessibilityAddTraits(selected ? .isSelected : [])
                    .listRowInsets(EdgeInsets())
                    .listRowBackground(Color(uiColor: .systemBackground))
                    .listRowSeparator(.hidden)
                    .accessibilityIdentifier("pad.item.\(cipher.openVaultID)")
                }
                if visible.isEmpty, model.canPresentCounts {
                    emptyList
                        .frame(maxWidth: .infinity)
                        .listRowSeparator(.hidden)
                        .selectionDisabled()
                }
            }
            .listStyle(.inset)
            .contentMargins(.horizontal, Spacing.sm, for: .scrollContent)
            .scrollContentBackground(.hidden)
            .background(Color(uiColor: .systemBackground))
            .vaultRefreshable(model)
            .navigationTitle(title)
            .toolbar(removing: .title)
            .toolbar(removing: .sidebarToggle)
            .navigationSplitViewColumnWidth(min: 275, ideal: sidebarVisible ? LayoutMetric.padListWidthWithSidebar : LayoutMetric.padListWidth, max: 420)
            .toolbar {
                ToolbarItemGroup(placement: .topBarTrailing) {
                    if !sidebarVisible {
                        Button("设置", systemImage: "gearshape", action: onSettings)
                            .accessibilityIdentifier("navigation.settings")
                    }
                    VaultSortMenu(selection: $sort, symbol: "arrow.up.arrow.down")
                    if scope != .archive, scope != .trash {
                        Button("新建条目", systemImage: "plus", action: onAdd)
                            .accessibilityIdentifier("pad.newItem")
                    } else if scope == .trash {
                        EmptyTrashButton(model: model, vault: vault, pending: $permanentDeletion, busy: $emptyingTrash)
                    }
                }
            }
        } detail: {
            if let cipher = visible.first(where: { $0.openVaultID == selectedID }) {
                ItemDetailView(model: ItemDetailModel(cipher: cipher), vault: vault, isSplitDetail: true,
                               onSelectClone: { id in if selectedID == cipher.openVaultID { pendingCloneID = id } }) {
                    Task { await model.load() }
                }
                .id(cipher.openVaultID)
                .disabled(emptyingTrash)
            } else if model.hasLoadedContent {
                ContentUnavailableView("选择一个条目", systemImage: "rectangle.split.2x1")
            } else {
                Color.clear.accessibilityHidden(true)
            }
        }
        .navigationSplitViewStyle(.balanced)
        .onChange(of: scope) { _, _ in pendingCloneID = nil }
        .onChange(of: selectedID) { _, _ in pendingCloneID = nil }
        .onChange(of: model.errorMessage) { _, error in if error != nil { pendingCloneID = nil } }
        .onChange(of: pendingCloneID.flatMap { id in model.items.first { $0.id == id }?.id }) { _, loadedID in
            if let loadedID {
                pendingCloneID = nil
                if isActive { onClone(loadedID) }
            }
        }
        .onChange(of: tabBarPlacement) { _, placement in
            if let placement { onSidebarChange(placement == .sidebar) }
        }
        .onChange(of: visible.map(\.openVaultID), initial: true) { _, ids in
            if isActive, selectedID.map({ ids.contains($0) }) != true { selectedID = ids.first }
        }
        .onChange(of: isActive) { _, active in
            if !active { pendingCloneID = nil }
            if active, !visible.contains(where: { $0.openVaultID == selectedID }) { selectedID = visible.first?.openVaultID }
        }
    }

    private var selectedRowBackground: some View {
        let shape = RoundedRectangle(cornerRadius: 16, style: .continuous)
        return shape.fill(Color.accentColor.opacity(contrast == .increased ? 0.22 : 0.14))
            .overlay {
                if contrast == .increased || differentiateWithoutColor {
                    shape.strokeBorder(contrast == .increased ? Color.accentColor : Palette.secondaryText, lineWidth: 1.5)
                }
            }
            .background(Color(uiColor: .systemBackground))
    }

    @ViewBuilder private var emptyList: some View {
        switch scope {
        case .archive: ContentUnavailableView("没有归档的条目", systemImage: "archivebox")
        case .trash: ContentUnavailableView("回收站是空的", systemImage: "trash")
        case .folder: ContentUnavailableView("此文件夹为空", systemImage: "folder")
        default: ContentUnavailableView("没有条目", systemImage: "tray")
        }
    }
}
