import Accessibility
import SwiftUI
import DesignSystem
import UIShared
import VaultModels
import VaultRepository

struct MacMainView: View {
    let auth: AuthService
    let vault: VaultService
    let syncModel: SyncStatusModel
    let dataRevision: UInt64
    let onLock: () async -> Void

    @State private var listModel: VaultListModel
    @State private var generatorModel: GeneratorModel
    @State private var destination: MacDestination = .all
    @State private var selectedID: String?
    @State private var searchText = ""
    @State private var searchPresented = false
    @FocusState private var searchFocused: Bool
    @State private var sort: MacItemSort = .name
    @State private var columns: NavigationSplitViewVisibility = .all
    @State private var sheet: WorkspaceSheet?
    @State private var showingNewSend = false
    @State private var sendCount: Int?
    @State private var editingFolder = false
    @State private var folderID: String?
    @State private var folderName = ""
    @State private var confirmation: Confirmation?
    @State private var feedback: OperationFeedback?
    @State private var failure: String?
    @State private var changing = false
    @State private var recentSync = false
    @State private var operationTask: Task<Void, Never>?

    init(auth: AuthService, vault: VaultService, syncModel: SyncStatusModel, dataRevision: UInt64,
         onLock: @escaping () async -> Void) {
        self.auth = auth
        self.vault = vault
        self.syncModel = syncModel
        self.dataRevision = dataRevision
        self.onLock = onLock
        _listModel = State(initialValue: VaultListModel(vault: vault))
        _generatorModel = State(initialValue: GeneratorModel(vault: vault))
    }

    private var entries: [MacTOTPEntry] { MacTOTPEntry.entries(from: listModel.items) }
    private var query: String { searchText.trimmingCharacters(in: .whitespacesAndNewlines) }
    private var visibleEntries: [MacTOTPEntry] {
        entries.filter { query.isEmpty || $0.cipher.matchesMacSearch(query) }
    }
    private var visibleItems: [PlaintextCipher] {
        let source = switch destination {
        case .trash: listModel.trashedItems
        case .archive: listModel.archivedItems
        default: listModel.items
        }
        return source.filter { destination.matches($0) && (query.isEmpty || $0.matchesMacSearch(query)) }
            .sorted(by: sort.precedes)
    }
    private var selectedCipher: PlaintextCipher? { visibleItems.first { $0.macStableID == selectedID } }
    private var selectedFolderID: String? {
        guard case .folder(let id) = destination else { return nil }
        return id
    }
    private var title: String {
        listModel.folders.first { $0.id == selectedFolderID }?.name ?? destination.title
    }
    private var counts: MacSidebarCounts {
        MacSidebarCounts(items: listModel.items, authenticators: entries.count, archived: listModel.archivedItems.count,
                         trashed: listModel.trashedItems.count, sends: sendCount)
    }

    var body: some View {
        layout
            .navigationSplitViewStyle(.balanced)
            .searchable(text: $searchText, isPresented: $searchPresented, placement: .toolbar,
                        prompt: Text(destination == .send ? "搜索 Send" : "搜索保险库"))
            .searchFocused($searchFocused)
            .focusedSceneValue(\.macWorkspaceActions, sheet == nil && !showingNewSend && !editingFolder && confirmation == nil && failure == nil ? actions : nil)
            .sheet(item: $sheet, content: sheetContent)
            .alert(folderID == nil ? "新建文件夹" : "重命名文件夹", isPresented: $editingFolder) {
                TextField("文件夹名称", text: $folderName)
                Button("取消", role: .cancel) {}
                Button("存储", action: saveFolder).disabled(folderName.nilIfBlank == nil)
            }
            .confirmationDialog(confirmation?.title ?? "", isPresented: Binding(get: { confirmation != nil }, set: { if !$0 { confirmation = nil } }),
                                titleVisibility: .visible, presenting: confirmation) { pending in
                Button(pending.buttonTitle, role: .destructive) { confirm(pending) }
                Button("取消", role: .cancel) {}
            } message: { pending in Text(pending.message) }
            .alert("操作未完成", isPresented: Binding(get: { failure != nil }, set: { if !$0 { failure = nil } })) {
                Button("好", role: .cancel) {}
            } message: { Text(failure ?? "") }
            .overlay(alignment: .bottom) { feedbackView }
            .task(id: feedback?.id) {
                guard feedback != nil else { return }
                do { try await Task.sleep(for: .seconds(4)); feedback = nil } catch {}
            }
            .task {
                await reloadVault()
                guard !Task.isCancelled, syncModel.lastSync == nil else { return }
                await syncModel.sync()
            }
            .task(id: syncModel.lastSync) {
                guard let last = syncModel.lastSync, last.timeIntervalSinceNow >= -2 else { recentSync = false; return }
                recentSync = true
                do { try await Task.sleep(for: .seconds(2)); recentSync = false } catch {}
            }
            .onChange(of: dataRevision) { Task { await reloadVault() } }
            .onChange(of: destination) { _, _ in normalizeSelection() }
            .onChange(of: searchText) { _, _ in normalizeSelection() }
            .onChange(of: searchPresented) { _, active in
                if active && destination == .generator { destination = .all }
            }
            .onDisappear {
                operationTask?.cancel()
                listModel.clearDecryptedItems()
            }
    }

    @ViewBuilder private var layout: some View {
        if destination.hasList {
            NavigationSplitView(columnVisibility: $columns) {
                sidebar
            } content: {
                listColumn.navigationSplitViewColumnWidth(min: 245, ideal: LayoutMetric.desktopListWidth, max: 390)
            } detail: {
                detailColumn
            }
        } else {
            NavigationSplitView(columnVisibility: $columns) {
                sidebar
            } detail: {
                if destination == .send {
                    MacSendView(vault: vault, showComposer: $showingNewSend, query: searchText,
                                onCountChange: { sendCount = $0 }, dataRevision: dataRevision)
                        .navigationTitle("Send")
                } else {
                    MacGeneratorView(model: generatorModel).navigationTitle("生成器")
                }
            }
        }
    }

    private var sidebar: some View {
        MacSidebarView(selection: $destination, counts: counts, folders: listModel.folders,
                       onNewFolder: { editFolder(nil) }, onRenameFolder: editFolder) { folder in
            let allItems = listModel.items + listModel.archivedItems + listModel.trashedItems
            confirmation = .folder(id: folder.id, count: allItems.count { $0.folderID == folder.id })
        }
        .navigationSplitViewColumnWidth(min: 180, ideal: 248, max: 300)
    }

    @ViewBuilder private var listColumn: some View {
        if destination == .authenticator {
            MacAuthenticatorListView(entries: visibleEntries, selection: userSelection, isFiltering: !query.isEmpty,
                                     onNewItem: { sheet = .item })
        } else {
            MacItemListView(items: visibleItems, isLoading: listModel.isLoading, errorMessage: listModel.errorMessage,
                            isSearching: !query.isEmpty, destination: destination, selection: userSelection, sort: $sort,
                            onEmptyTrash: { confirmation = .empty(ids: listModel.trashedItems.compactMap(\.id)) },
                            hasTrash: !changing && !listModel.trashedItems.isEmpty)
                .navigationTitle(title)
                .navigationSubtitle(syncModel.isSyncing ? "正在同步…" : recentSync ? "已同步" : "")
                .toolbar {
                    ToolbarItemGroup(placement: .primaryAction) {
                        Button("立即同步", systemImage: "arrow.clockwise", action: sync).disabled(syncModel.isSyncing)
                        if !destination.isHiddenCollection {
                            Button("新建条目", systemImage: "plus") { sheet = .item }
                        }
                    }
                }
        }
    }

    @ViewBuilder private var detailColumn: some View {
        if destination == .authenticator, let entry = visibleEntries.first(where: { $0.id == selectedID }) {
            MacAuthenticatorDetailView(entry: entry, onCopy: {
                if let id = entry.cipher.id { Task { await vault.recordUse(id: id) } }
            }) {
                destination = .all
                selectedID = entry.id
            }.id(entry.id)
        } else if let cipher = selectedCipher {
            let folderName = listModel.folders.first { $0.id == cipher.folderID }?.name
            if destination.isHiddenCollection {
                hiddenDetail(cipher, folderName: folderName)
            } else {
                MacItemDetailView(cipher: cipher, vault: vault, folderName: folderName,
                                  onMoveToTrash: { change(cipher, action: .trash) }, onArchive: { change(cipher, action: .archive) }) {
                    Task { await reloadVault() }
                }.id(cipher.macStableID)
            }
        } else {
            ContentUnavailableView(destination == .authenticator ? "选择验证码" : "未选择条目", systemImage: destination.systemImage,
                                   description: Text("从列表中选择一个条目以查看详情。"))
        }
    }

    private func hiddenDetail(_ cipher: PlaintextCipher, folderName: String?) -> some View {
        let isTrashed = destination == .trash
        let date = isTrashed ? cipher.deletedDate : cipher.archivedDate
        return ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 14) {
                    BrandBadge(cipher.name, diameter: 54)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(cipher.name.nilIfBlank ?? "未命名条目").font(.system(size: 26, weight: .bold)).accessibilityAddTraits(.isHeader)
                        if let date {
                            Text("\(cipher.macTypeLabel) · \(date.formatted(date: .abbreviated, time: .omitted))\(isTrashed ? "删除" : "归档")")
                                .foregroundStyle(.secondary)
                        } else {
                            Text(cipher.macTypeLabel).foregroundStyle(.secondary)
                        }
                    }
                }.padding(.bottom, 10)
                hiddenActions(cipher)
                OpenVaultCard(cornerRadius: CornerRadius.macCard) {
                    VStack(alignment: .leading) {
                        LabeledContent("文件夹", value: folderName ?? "无文件夹")
                        if let username = cipher.login?.username?.nilIfBlank {
                            Divider(); LabeledContent("用户名", value: username)
                        }
                        if cipher.login?.password?.isEmpty == false {
                            Divider(); LabeledContent("密码", value: "••••••••")
                        }
                        if let uri = cipher.login?.uris.first?.uri, let host = URL(string: uri)?.host {
                            Divider(); LabeledContent("网站", value: host)
                        }
                        if cipher.login == nil, let subtitle = cipher.macSubtitle {
                            Divider(); LabeledContent(cipher.macTypeLabel, value: subtitle)
                        }
                    }
                }
            }
            .frame(maxWidth: 680, alignment: .leading).padding(24)
            .frame(maxWidth: .infinity, alignment: .top)
            .privacySensitive()
        }
    }

    private func hiddenActions(_ cipher: PlaintextCipher) -> some View {
        HStack {
            Label(destination == .trash ? "此条目在回收站中" : "此条目已归档", systemImage: destination.systemImage)
            Spacer()
            if destination == .trash {
                Button("永久删除…", role: .destructive) {
                    if let id = cipher.id { confirmation = .item(id: id) }
                }
            }
            Button(destination == .trash ? "恢复" : "取消归档") { change(cipher, action: destination == .trash ? .restore : .unarchive) }
                .buttonStyle(.borderedProminent)
        }
        .frame(minHeight: LayoutMetric.desktopRowHeight)
        .padding(.horizontal, 12)
        .background(Palette.contentBackground, in: RoundedRectangle(cornerRadius: CornerRadius.macCard))
        .disabled(changing || cipher.id == nil)
    }

    @ViewBuilder private func sheetContent(_ sheet: WorkspaceSheet) -> some View {
        switch sheet {
        case .item:
            MacItemEditView(vault: vault, initialType: destination.initialType, initialFolderID: selectedFolderID) { id in
                self.sheet = nil
                Task {
                    await reloadVault()
                    searchText = ""
                    if !visibleItems.contains(where: { $0.id == id }) { destination = .all }
                    selectedID = id
                }
            }
        case .importItems, .exportItems:
            VaultTransferView(mode: sheet == .importItems ? .importItems : .exportItems, auth: auth, vault: vault, onImported: reloadVault)
        }
    }

    private var actions: MacWorkspaceActions {
        let selected = changing || destination.isHiddenCollection ? nil : selectedCipher
        return MacWorkspaceActions(newItem: { sheet = .item }, newFolder: { editFolder(nil) },
                                   newSend: { destination = .send; showingNewSend = true },
                                   showImport: { sheet = .importItems }, showExport: { sheet = .exportItems },
                                   search: { searchPresented = true; searchFocused = true }, sync: syncModel.isSyncing ? nil : sync,
                                   archive: selected.map { cipher in { change(cipher, action: .archive) } },
                                   trash: selected.map { cipher in { change(cipher, action: .trash) } },
                                   lock: { Task { await onLock() } })
    }

    private func editFolder(_ folder: PlaintextFolder?) {
        folderID = folder?.id
        folderName = folder?.name ?? ""
        editingFolder = true
    }

    private func saveFolder() {
        guard let name = folderName.nilIfBlank else { return }
        let existing = folderID
        perform {
            if let existing {
                try await vault.renameFolder(id: existing, name: name)
            } else {
                let id = try await vault.createFolder(name: name)
                destination = .folder(id)
            }
        }
    }

    private func change(_ cipher: PlaintextCipher, action: ItemChange) {
        guard let id = cipher.id else { return }
        change(id: id, action: action)
    }

    private func change(id: String, action: ItemChange) {
        perform {
            switch action {
            case .trash: try await vault.trashCipher(id: id)
            case .restore: try await vault.restoreCipher(id: id)
            case .archive: try await vault.archiveCipher(id: id)
            case .unarchive: try await vault.unarchiveCipher(id: id)
            }
            feedback = OperationFeedback(message: action.message, undoID: id, undo: action.undo)
        }
    }

    private func confirm(_ pending: Confirmation) {
        perform {
            switch pending {
            case .item(let id): try await vault.permanentlyDeleteCipher(id: id)
            case .empty(let ids):
                for id in ids {
                    try Task.checkCancellation()
                    try await vault.permanentlyDeleteCipher(id: id)
                }
            case .folder(let id, _):
                try await vault.deleteFolder(id: id)
                if destination == .folder(id) { destination = .unfiled }
            }
            feedback = OperationFeedback(message: pending.result)
        }
    }

    private func perform(_ operation: @escaping @MainActor () async throws -> Void) {
        guard !changing else { return }
        changing = true
        feedback = nil
        operationTask = Task {
            defer { changing = false; operationTask = nil }
            do { try await operation() }
            catch is CancellationError { return }
            catch { failure = "请检查服务器连接，完成同步后再试。" }
            guard !Task.isCancelled else { return }
            await reloadVault()
        }
    }

    @ViewBuilder private var feedbackView: some View {
        if let feedback {
            HStack {
                Text(feedback.message)
                if let action = feedback.undo, let id = feedback.undoID {
                    Button("撤销") { change(id: id, action: action) }.disabled(changing)
                }
            }
            .padding(.horizontal, 14).padding(.vertical, 8)
            .glassStyle(in: Capsule()).padding(.bottom, 20)
            .accessibilityElement(children: .contain)
            .onChange(of: feedback.id, initial: true) { AccessibilityNotification.Announcement(feedback.message).post() }
        }
    }

    private func sync() {
        Task {
            if !(await syncModel.sync()), let error = syncModel.errorMessage { failure = error }
        }
    }

    private func reloadVault() async {
        await listModel.load()
        if let id = selectedFolderID, listModel.errorMessage == nil, !listModel.folders.contains(where: { $0.id == id }) {
            destination = .all
        }
        normalizeSelection()
    }

    private func normalizeSelection() {
        let ids = destination == .authenticator ? visibleEntries.map(\.id) : visibleItems.map(\.macStableID)
        if !ids.contains(where: { $0 == selectedID }) { selectedID = ids.first }
    }

    private var userSelection: Binding<String?> {
        Binding(get: { selectedID }, set: { selection in
            selectedID = selection
            guard let selection, !destination.isHiddenCollection,
                  listModel.items.contains(where: { $0.id == selection }) else { return }
            Task { await vault.recordUse(id: selection) }
        })
    }
}

private enum WorkspaceSheet: String, Identifiable {
    case item, importItems, exportItems
    var id: Self { self }
}

private enum ItemChange {
    case trash, restore, archive, unarchive

    var message: String {
        switch self {
        case .trash: "已移到回收站"
        case .restore: "已恢复条目"
        case .archive: "已归档"
        case .unarchive: "已取消归档"
        }
    }

    var undo: ItemChange? {
        switch self {
        case .trash: .restore
        case .archive: .unarchive
        default: nil
        }
    }
}

private struct OperationFeedback: Identifiable {
    let id = UUID()
    let message: String
    var undoID: String?
    var undo: ItemChange?
}

private enum Confirmation {
    case item(id: String), empty(ids: [String]), folder(id: String, count: Int)

    var title: String {
        switch self {
        case .item: "永久删除这个条目？"
        case .empty(let ids): "永久删除回收站中的 \(ids.count) 个条目？"
        case .folder: "删除这个文件夹？"
        }
    }

    var message: String {
        switch self {
        case .folder(_, let count): "其中 \(count) 个条目将移到“无文件夹”，条目不会被删除。"
        case .item, .empty: "永久删除后无法恢复。"
        }
    }

    var buttonTitle: String {
        switch self {
        case .folder: "删除文件夹"
        case .item, .empty: "永久删除"
        }
    }

    var result: String {
        switch self {
        case .folder: "已删除文件夹"
        case .item: "已永久删除条目"
        case .empty: "已清空回收站"
        }
    }
}

private extension PlaintextCipher {
    func matchesMacSearch(_ query: String) -> Bool {
        name.localizedCaseInsensitiveContains(query)
        || macSubtitle?.localizedCaseInsensitiveContains(query) == true
        || login?.uris.contains { $0.uri.localizedCaseInsensitiveContains(query) } == true
    }
}
