import Accessibility
import SwiftUI
import UIShared
import DesignSystem
import VaultRepository

@available(iOS 27.0, *)
public struct VaultListView: View {
    let model: VaultListModel
    let vault: VaultService
    let onOpenSettings: () -> Void

    @Environment(\.vaultSyncModel) private var syncModel
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    @Environment(\.colorSchemeContrast) private var contrast
    @State private var type: VaultWorkspaceSection = .all
    @State private var sort: VaultSortOrder = .name
    @State private var editingFolder: VaultFolderEditor?
    @State private var pinnedDetailID: String?
    @State private var adding = false

    public init(model: VaultListModel, vault: VaultService, onOpenSettings: @escaping () -> Void) {
        self.model = model
        self.vault = vault
        self.onOpenSettings = onOpenSettings
    }

    public var body: some View {
        let visible = sort.sorted(model.items.filter { $0.isIncluded(in: type) })
        List {
            if let syncModel, syncModel.hasOutstandingChanges || syncModel.errorMessage != nil || syncModel.isOutboxStatusUnavailable {
                Section { SyncAttentionButton(model: syncModel, onOpenSettings: onOpenSettings) }
            }
            if !model.canPresentCounts {
                VaultReadStatus(model: model)
            } else {
                Section {
                    VaultFilterChips(selection: $type, items: model.items)
                        .listRowInsets(EdgeInsets())
                        .listRowBackground(Color.clear)
                        .listRowSeparator(.hidden)
                }
            }
            if type == .all, model.hasLoadedContent {
                let favorites = sort.sorted(model.items.filter(\.favorite))
                if !favorites.isEmpty {
                    Section { pinnedGrid(favorites) } header: {
                        VaultGroupHeading("置顶").vaultHeadingInsets()
                    }
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
                    .vaultHeadingInsets()
                }
            }
            if model.hasLoadedContent, !visible.isEmpty || model.canPresentCounts {
                Section {
                    if !visible.isEmpty {
                        VaultItemLinks(items: visible, model: model, vault: vault)
                    } else {
                        ContentUnavailableView(type == .all ? "保险库为空" : "没有此类型的条目",
                                               systemImage: "tray")
                    }
                } header: {
                    HStack(alignment: .firstTextBaseline) {
                        VaultGroupHeading(type.title)
                        Spacer()
                        Text("按\(sort.title)").font(.footnote)
                            .foregroundStyle(contrast == .increased ? Palette.primaryText : Palette.secondaryText)
                    }
                    .textCase(nil)
                    .vaultHeadingInsets()
                }
            }
            if model.hasLoadedContent {
                Section {
                    hiddenLink(.archive, count: model.archivedItems.count)
                    hiddenLink(.trash, count: model.trashedItems.count)
                } header: { VaultGroupHeading("隐藏的条目").vaultHeadingInsets() }
            }
        }
        .listStyle(.insetGrouped)
        .listSectionSpacing(Spacing.lg)
        .contentMargins(.top, Spacing.sm, for: .scrollContent)
        .contentMargins(.horizontal, Spacing.lg, for: .scrollContent)
        .environment(\.defaultMinListRowHeight, LayoutMetric.phoneRowHeight)
        .vaultRefreshable(model)
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
                Button("新建条目", systemImage: "plus") { adding = true }
                    .accessibilityIdentifier("vault.newItem")
            }
        }
        .vaultFolderDialogs(editor: $editingFolder, model: model, vault: vault)
        .vaultCreationFlow(isPresented: $adding, model: model, vault: vault)
        .navigationDestination(item: $pinnedDetailID) { id in
            if let cipher = model.items.first(where: { $0.openVaultID == id }) {
                ItemDetailView(model: ItemDetailModel(cipher: cipher), vault: vault) {
                    Task { await model.reloadCurrentView() }
                }
            } else {
                ContentUnavailableView("无法读取条目", systemImage: "exclamationmark.circle")
            }
        }
    }

    private func pinnedGrid(_ favorites: [PlaintextCipher]) -> some View {
        let columns = Array(repeating: GridItem(.flexible(), spacing: Spacing.xs, alignment: .top),
                            count: dynamicTypeSize.isAccessibilitySize ? 2 : 4)
        return LazyVGrid(columns: columns, spacing: Spacing.md) {
            ForEach(favorites, id: \.openVaultID) { cipher in
                Button {
                    pinnedDetailID = cipher.openVaultID
                } label: {
                    VStack(spacing: Spacing.sm) {
                        BrandBadge(cipher, diameter: 52)
                        Text(cipher.openVaultName)
                            .font(.footnote.weight(.medium))
                            .lineLimit(dynamicTypeSize.isAccessibilitySize ? nil : 2)
                            .multilineTextAlignment(.center)
                    }
                    .frame(maxWidth: .infinity, alignment: .top)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityLabel(cipher.openVaultName)
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
                if model.canPresentCounts {
                    Text(count, format: .number).foregroundStyle(.secondary).monospacedDigit()
                }
            }
        }
        .accessibilityIdentifier("vault.\(section.rawValue)")
    }
}

@available(iOS 27.0, *)
extension View {
    func vaultCreationFlow(isPresented: Binding<Bool>, model: VaultListModel, vault: VaultService,
                           folderID: String? = nil) -> some View {
        modifier(VaultCreationFlow(isPresented: isPresented, model: model, vault: vault, folderID: folderID))
    }
}

@available(iOS 27.0, *)
private struct VaultCreationFlow: ViewModifier {
    @Binding var isPresented: Bool
    let model: VaultListModel
    let vault: VaultService
    let folderID: String?
    @State private var savedID: String?
    @State private var detailID: String?

    func body(content: Content) -> some View {
        content
            .sheet(isPresented: $isPresented, onDismiss: openSavedItem) {
                NavigationStack {
                    ItemEditView(vault: vault, initialFolderID: folderID) { id in
                        savedID = id
                        isPresented = false
                    }
                }
                .presentationSizing(.form)
                .presentationDragIndicator(.visible)
            }
            .navigationDestination(item: $detailID) { id in
                if let cipher = model.items.first(where: { $0.id == id }) {
                    ItemDetailView(model: ItemDetailModel(cipher: cipher), vault: vault) {
                        Task { await model.reloadCurrentView() }
                    }
                } else {
                    ContentUnavailableView {
                        Label("无法读取条目", systemImage: "exclamationmark.circle")
                    } actions: {
                        Button("重新载入") { Task { await model.load() } }
                    }
                }
            }
    }

    private func openSavedItem() {
        guard let id = savedID else { return }
        savedID = nil
        Task {
            await model.load()
            detailID = id
        }
    }
}

private extension View {
    func vaultHeadingInsets() -> some View {
        listRowInsets(EdgeInsets(top: 0, leading: Spacing.xs, bottom: Spacing.sm, trailing: Spacing.xs))
    }
}

@available(iOS 27.0, *)
struct VaultSearchView: View {
    let model: VaultListModel
    let vault: VaultService
    let onSelect: ((PlaintextCipher) -> Void)?
    @Environment(\.horizontalSizeClass) private var sizeClass
    @State private var type: VaultWorkspaceSection = .all

    var body: some View {
        let results = VaultSortOrder.name.sorted(model.items.filter { $0.isIncluded(in: type) })
        List {
            if sizeClass == .regular {
                Text("搜索")
                    .font(.title.bold())
                    .foregroundStyle(Palette.primaryText)
                    .accessibilityAddTraits(.isHeader)
                    .listRowInsets(EdgeInsets(top: 0, leading: Spacing.xs, bottom: 0, trailing: Spacing.xs))
                    .listRowBackground(Color.clear)
                    .listRowSeparator(.hidden)
            }
            Section {
                VaultFilterChips(selection: $type, items: model.items, wraps: true, search: true)
                    .listRowInsets(EdgeInsets())
                    .listRowBackground(Color.clear)
                    .listRowSeparator(.hidden)
            } header: { Text("按类型查找") }
            if !model.canPresentCounts { VaultReadStatus(model: model) }
            if model.hasLoadedContent, !model.isLoading, !results.isEmpty || model.canPresentCounts {
                Section {
                    if !results.isEmpty {
                        VaultItemLinks(items: results, model: model, vault: vault, onSelect: onSelect)
                    } else {
                        ContentUnavailableView("没有结果", systemImage: "magnifyingglass",
                                               description: Text(emptyDescription))
                    }
                } header: {
                    if model.canPresentCounts {
                        Text(model.query.isEmpty && type == .all ? "全部条目" : "\(results.count) 个结果")
                    }
                }
            }
        }
        .listStyle(.insetGrouped)
        .contentMargins(.horizontal, Spacing.lg, for: .scrollContent)
        .textCase(nil)
        .frame(maxWidth: sizeClass == .regular ? LayoutMetric.padSearchWidth : .infinity)
        .frame(maxWidth: .infinity)
        .background(Palette.groupedBackground)
        .navigationTitle(sizeClass == .regular ? "" : "搜索")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar(sizeClass == .regular ? .hidden : .automatic, for: .navigationBar)
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
    var onSelect: ((PlaintextCipher) -> Void)? = nil
    @Environment(\.vaultFeedback) private var feedback
    @Environment(\.scenePhase) private var scenePhase
    @State private var operationError: String?
    @State private var copyReceipt: CopyReceipt?
    @State private var pendingCopy: Task<Void, Never>?

    private struct CopyReceipt: Identifiable {
        let itemID: String
        let id = UUID()
        let expires = ContinuousClock.now.advanced(by: .milliseconds(1600))
    }

    var body: some View {
        ForEach(items, id: \.openVaultID, content: row)
        .task(id: copyReceipt?.id) {
            guard let receipt = copyReceipt else { return }
            do { try await Task.sleep(until: receipt.expires, clock: .continuous) } catch { return }
            if copyReceipt?.id == receipt.id { copyReceipt = nil }
        }
        .onDisappear { pendingCopy?.cancel() }
        .alert("操作未完成", isPresented: Binding(get: { operationError != nil },
                                              set: { if !$0 { operationError = nil } })) {
            Button("好", role: .cancel) {}
        } message: { Text(operationError ?? "请刷新保险库后重试。") }
    }

    private func row(_ cipher: PlaintextCipher) -> some View {
        let copied = copyReceipt.map { $0.itemID == cipher.openVaultID && $0.expires > .now } ?? false
        return Group {
            if let onSelect {
                Button { onSelect(cipher) } label: {
                    itemRow(cipher, copied: copied, showsDisclosure: true)
                }
                .buttonStyle(.plain)
            } else {
                NavigationLink {
                    ItemDetailView(model: ItemDetailModel(cipher: cipher), vault: vault) {
                        Task { await model.reloadCurrentView() }
                    }
                } label: {
                    itemRow(cipher, copied: copied, showsDisclosure: false)
                }
            }
        }
        .listRowInsets(EdgeInsets(top: 0, leading: Spacing.lg, bottom: 0, trailing: Spacing.lg))
        .accessibilityIdentifier("vault.item.\(cipher.openVaultID)")
        .accessibilityValue("已拷贝", isEnabled: copied)
        .swipeActions(edge: .trailing, allowsFullSwipe: false) { copyAction(for: cipher) }
        .swipeActions(edge: .leading, allowsFullSwipe: false) { trashAction(for: cipher) }
        .contextMenu {
            copyAction(for: cipher)
            trashAction(for: cipher)
            if let id = cipher.id {
                Button("归档", systemImage: "archivebox") { move(id: id, to: .archive) }
                    .accessibilityIdentifier("vault.archive.\(id)")
            }
        }
    }

    private func itemRow(_ cipher: PlaintextCipher, copied: Bool, showsDisclosure: Bool) -> some View {
        HStack(spacing: 0) {
            VaultItemRow(cipher: cipher, showsFavorite: false, showsDisclosureIndicator: showsDisclosure && !copied)
            if copied { InlineCopyIndicator() }
        }
        .contentShape(Rectangle())
    }

    private func quickPassword(_ cipher: PlaintextCipher) -> String? {
        guard cipher.isIncluded(in: .logins), cipher.deletedDate == nil, cipher.archivedDate == nil,
              cipher.reprompt == 0, cipher.organizationID == nil,
              let password = cipher.login?.password, !password.isEmpty else { return nil }
        return password
    }

    @ViewBuilder private func copyAction(for cipher: PlaintextCipher) -> some View {
        if let id = cipher.id, quickPassword(cipher) != nil {
            Button("拷贝密码", systemImage: "doc.on.doc") { copyPassword(id: id) }
                .tint(.blue)
                .accessibilityIdentifier("vault.copyPassword.\(id)")
        }
    }

    private func copyPassword(id: String) {
        pendingCopy?.cancel()
        pendingCopy = Task {
            do {
                let latest = try await vault.cipher(id: id)
                guard !Task.isCancelled, scenePhase == .active, model.hasLoadedContent,
                      model.items.contains(where: { $0.id == id }) else { return }
                guard let password = quickPassword(latest) else {
                    operationError = "此条目已更改，无法拷贝密码。请刷新保险库后重试。"
                    return
                }
                Clipboard.copy(password)
                copyReceipt = CopyReceipt(itemID: id)
                AccessibilityNotification.Announcement("已拷贝").post()
                await vault.recordUse(id: id)
            } catch {
                if !Task.isCancelled { operationError = "无法读取密码，请刷新保险库后重试。" }
            }
        }
    }

    @ViewBuilder private func trashAction(for cipher: PlaintextCipher) -> some View {
        if let id = cipher.id {
            Button(role: .destructive) { move(id: id, to: .trash) } label: {
                Label("移到回收站", systemImage: "trash")
            }
            .accessibilityIdentifier("vault.trash.\(id)")
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
            .foregroundStyle(Palette.primaryText)
            .textCase(nil)
            .accessibilityAddTraits(.isHeader)
    }
}

struct VaultReadStatus: View {
    let model: VaultListModel
    @Environment(\.vaultSyncModel) private var syncModel

    var body: some View {
        if let message = model.errorMessage {
            VStack(alignment: .leading, spacing: Spacing.xs) {
                Label(message, systemImage: "exclamationmark.triangle")
                    .font(.subheadline).foregroundStyle(.red)
                Button("重试") {
                    Task {
                        if model.hasLoadedContent {
                            if let syncModel { await syncModel.sync() }
                            else { await model.refresh() }
                        } else { await model.reloadCurrentView() }
                    }
                }
                .buttonStyle(.borderless)
                .frame(minHeight: LayoutMetric.minimumTapTarget)
                .accessibilityIdentifier("vault.retry")
            }
        } else if model.isLoading || !model.hasLoadedContent {
            ProgressView().frame(maxWidth: .infinity).accessibilityLabel("正在载入")
        }
    }
}
