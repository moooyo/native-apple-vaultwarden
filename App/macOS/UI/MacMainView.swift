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
    @State private var codeClock = MacCodeClock()
    @State private var entries: [MacTOTPEntry] = []
    @State private var destination: MacDestination = .all
    @State private var selectedID: String?
    @State private var searchText = ""
    @State private var searchPresented = false
    @FocusState private var searchFocused: Bool
    @State private var sort: MacItemSort = .name
    @State private var columns: NavigationSplitViewVisibility = .all
    @State private var sheet: WorkspaceSheet?
    @State private var showingNewSend = false
    @State private var observedSends: (attempt: UInt64, count: Int?)?
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
         initialDestination: MacDestination = .all,
         onLock: @escaping () async -> Void) {
        self.auth = auth
        self.vault = vault
        self.syncModel = syncModel
        self.dataRevision = dataRevision
        self.onLock = onLock
        _destination = State(initialValue: initialDestination)
        _listModel = State(initialValue: VaultListModel(vault: vault))
        _generatorModel = State(initialValue: GeneratorModel(vault: vault))
    }

    private var query: String { searchText.trimmingCharacters(in: .whitespacesAndNewlines) }
    private var visibleEntries: [MacTOTPEntry] {
        let term = query
        return entries.filter { $0.cipher.matchesMacSearch(term, in: .authenticator) }
    }
    private var visibleItems: [PlaintextCipher] {
        let source = switch destination {
        case .trash: listModel.trashedItems
        case .archive: listModel.archivedItems
        default: listModel.items
        }
        let term = query
        let folderNames = destination.isHiddenCollection && !term.isEmpty
            ? listModel.folders.reduce(into: [String: String]()) { $0[$1.id] = $1.name } : [:]
        return source.filter { destination.matches($0) && $0.matchesMacSearch(term, in: destination, folderNames: folderNames) }
            .sorted(by: sort.precedes)
    }
    private var selectedCipher: PlaintextCipher? { visibleItems.first { $0.macStableID == selectedID } }
    private var title: String {
        listModel.folders.first { $0.id == destination.folderID }?.name ?? destination.title
    }
    private var counts: MacSidebarCounts? {
        guard listModel.canPresentCounts else { return nil }
        return MacSidebarCounts(items: listModel.items, authenticators: entries.count, archived: listModel.archivedItems.count,
                                trashed: listModel.trashedItems.count, sends: sendCount)
    }
    private var sendCount: Int? {
        guard vault.sendService != nil else { return nil }
        if let access = syncModel.syncAccess { return syncModel.isSyncing ? nil : access.sendCount }
        if let observedSends, observedSends.attempt == syncModel.syncAttempt { return observedSends.count }
        guard !syncModel.isSyncing, syncModel.errorMessage == nil else { return nil }
        return syncModel.lastOutcome?.sendCount
    }
    private var personalItemCount: Int? {
        guard listModel.canPresentCounts else { return nil }
        return listModel.items.count { $0.organizationID == nil } + listModel.archivedItems.count { $0.organizationID == nil }
    }
    private var searchPrompt: String {
        switch destination {
        case .authenticator: "筛选验证码"
        case .send: "搜索 Send"
        case .archive: "搜索归档"
        case .trash: "搜索回收站"
        default: "搜索保险库"
        }
    }

    private var hasPresentedDialog: Bool {
        sheet != nil || showingNewSend || editingFolder || confirmation != nil || failure != nil
    }

    var body: some View {
        searchableLayout
            .navigationSplitViewStyle(.balanced)
            .focusedSceneValue(\.macWorkspaceActions, hasPresentedDialog ? nil : actions)
            .sheet(item: $sheet, content: sheetContent)
            .alert(folderID == nil ? "新建文件夹" : "重命名文件夹", isPresented: $editingFolder) {
                TextField("文件夹名称", text: $folderName)
                Button("取消", role: .cancel) {}
                Button("存储", action: saveFolder).disabled(folderName.nilIfBlank == nil)
            }
            .confirmationDialog(confirmation?.title ?? "", isPresented: Binding(get: { confirmation != nil }, set: { if !$0 { confirmation = nil } }),
                                titleVisibility: .visible, presenting: confirmation) { pending in
                Button(pending.buttonTitle, role: .destructive) { confirm(pending) }
                Button("取消", role: .cancel) {}.keyboardShortcut(.defaultAction)
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
            .onChange(of: destination) { _, _ in searchText = ""; normalizeSelection() }
            .onChange(of: searchText) { _, _ in normalizeSelection() }
            .task(id: destination == .authenticator) {
                guard destination == .authenticator else { return }
                while !Task.isCancelled {
                    let now = Date.now
                    codeClock.date = now
                    let remaining = 1 - now.timeIntervalSince1970.truncatingRemainder(dividingBy: 1)
                    do { try await Task.sleep(for: .seconds(remaining)) } catch { return }
                }
            }
            .onDisappear {
                operationTask?.cancel()
                entries = []
                observedSends = nil
                listModel.clearDecryptedItems()
            }
    }

    @ViewBuilder private var searchableLayout: some View {
        if destination == .generator {
            layout
        } else {
            layout
                .searchable(text: $searchText, isPresented: $searchPresented, placement: .toolbar, prompt: Text(searchPrompt))
                .searchFocused($searchFocused)
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
                    MacSendView(vault: vault, showComposer: $showingNewSend,
                                query: SendWorkspaceSelection.scopedQuery($searchText) { destination == .send },
                                onCountChange: { count in
                                    if destination == .send { observedSends = (syncModel.syncAttempt, count) }
                                }, dataRevision: dataRevision, syncAccess: syncModel.syncAccess)
                        .navigationTitle("Send")
                } else {
                    MacGeneratorView(model: generatorModel).navigationTitle("生成器")
                }
            }
            .navigationTitle(destination.title)
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
            MacAuthenticatorListView(entries: listModel.canPresentCounts ? visibleEntries : [], clock: codeClock,
                                     model: listModel, selection: userSelection, isFiltering: !query.isEmpty,
                                     onNewItem: newItem, onRetry: retryRead)
        } else {
            MacItemListView(items: listModel.canPresentCounts ? visibleItems : [], model: listModel,
                            isSearching: !query.isEmpty, destination: destination, selection: userSelection, sort: $sort,
                            onRetry: retryRead, onEmptyTrash: { confirmation = .empty(TrashRemovalBatch(ids: listModel.trashedItems.compactMap(\.id))) },
                            hasTrash: listModel.canPresentCounts && !changing && listModel.trashedItems.contains { $0.id != nil })
                .navigationTitle(title)
                .navigationSubtitle(syncModel.isSyncing ? "正在同步…" : recentSync && syncModel.errorMessage == nil ? "已同步" : "")
                .toolbar {
                    ToolbarItemGroup(placement: .primaryAction) {
                        Button("立即同步", systemImage: "arrow.clockwise", action: sync).disabled(syncModel.isSyncing)
                        if !destination.isHiddenCollection {
                            Button("新建条目", systemImage: "plus", action: newItem)
                        }
                    }
                }
        }
    }

    @ViewBuilder private var detailColumn: some View {
        if !listModel.canPresentCounts {
            Color.clear.accessibilityHidden(true)
        } else if destination == .authenticator, let entry = visibleEntries.first(where: { $0.id == selectedID }) {
            MacAuthenticatorDetailView(entry: entry, clock: codeClock, onCopy: {
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
                                  onMoveToTrash: { change(cipher, action: .trash) }, onArchive: { change(cipher, action: .archive) },
                                  onEdit: { sheet = .edit(cipher) }) {
                    Task { await reloadVault() }
                }.id(cipher.macStableID)
            }
        } else if destination.isHiddenCollection && query.isEmpty && visibleItems.isEmpty {
            ContentUnavailableView(destination == .trash ? "回收站是空的" : "没有归档的条目", systemImage: destination.systemImage,
                                   description: Text(destination == .trash ? "移到回收站的条目会显示在这里。" : "归档的条目会显示在这里。"))
        } else {
            ContentUnavailableView(destination == .authenticator ? "选择验证码" : "未选择条目", systemImage: destination.systemImage,
                                   description: Text("从列表中选择一个条目以查看详情。"))
        }
    }

    private func hiddenDetail(_ cipher: PlaintextCipher, folderName: String?) -> some View {
        let isTrashed = destination == .trash
        let date = isTrashed ? cipher.deletedDate : cipher.archivedDate
        return MacDetailColumn {
            HStack(spacing: 16) {
                BrandBadge(cipher, diameter: 64)
                VStack(alignment: .leading, spacing: 3) {
                    Text(cipher.name.nilIfBlank ?? "未命名条目").font(.system(size: 26, weight: .bold)).accessibilityAddTraits(.isHeader)
                    if let date {
                        Text("\(cipher.macTypeLabel) · \(date.formatted(date: .abbreviated, time: .omitted))\(isTrashed ? "删除" : "归档")")
                            .foregroundStyle(.secondary)
                    } else {
                        Text(cipher.macTypeLabel).foregroundStyle(.secondary)
                    }
                }
            }.padding(.bottom, 12)
            hiddenActions(cipher)
            MacDetailCard {
                VStack(alignment: .leading, spacing: 0) {
                    MacDetailRow("文件夹") { Text(folderName ?? (cipher.folderID == nil ? "无文件夹" : "—")) }
                    if let username = cipher.login?.username?.nilIfBlank {
                        Divider().padding(.leading, 16); MacDetailRow("用户名") { Text(username) }
                    }
                    if cipher.login?.password?.isEmpty == false {
                        Divider().padding(.leading, 16); MacDetailRow("密码") { Text("••••••••").font(.body.monospaced()) }
                    }
                    if let uri = cipher.login?.uris.first?.uri, let host = macWebsiteURL(uri)?.host {
                        Divider().padding(.leading, 16); MacDetailRow("网站") { Text(host) }
                    }
                    if cipher.login == nil, let subtitle = cipher.macSubtitle {
                        Divider().padding(.leading, 16); MacDetailRow(cipher.macTypeLabel) { Text(subtitle) }
                    }
                }
            }
        }.privacySensitive()
    }

    private func hiddenActions(_ cipher: PlaintextCipher) -> some View {
        MacDetailCard {
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
                    .keyboardShortcut(destination == .trash && !searchFocused && !hasPresentedDialog ? .defaultAction : nil)
            }
            .frame(minHeight: 52)
            .padding(.horizontal, 12)
        }
        .disabled(changing || cipher.id == nil)
    }

    @ViewBuilder private func sheetContent(_ sheet: WorkspaceSheet) -> some View {
        switch sheet {
        case .item(let origin):
            MacItemEditView(vault: vault, initialType: origin.initialType, initialFolderID: origin.folderID,
                            requiresCode: origin == .authenticator) { id in
                self.sheet = nil
                Task {
                    await reloadVault()
                    if origin == .authenticator {
                        destination = .authenticator
                        if !visibleEntries.contains(where: { $0.id == id }) { searchText = "" }
                    } else {
                        searchText = ""
                        if !visibleItems.contains(where: { $0.id == id }) { destination = .all }
                    }
                    selectedID = id
                }
            }
        case .edit(let cipher):
            MacItemEditView(vault: vault, existing: cipher) { _ in Task { await reloadVault() } }
        case .transfer(let mode):
            VaultTransferView(mode: mode, auth: auth, vault: vault, personalItemCount: personalItemCount, onImported: reloadVault)
        }
    }

    private var actions: MacWorkspaceActions {
        let syncAction: (() -> Void)? = syncModel.isSyncing ? nil : { self.sync() }
        return MacWorkspaceActions(
            newItemTitle: destination == .authenticator ? "新建验证码…" : "新建条目…",
            newItem: newItem, newFolder: { editFolder(nil) },
            newSend: { destination = .send; showingNewSend = true },
            showImport: { sheet = .transfer(.importItems) }, showExport: { sheet = .transfer(.exportItems) },
            search: openSearch, sync: syncAction,
            archive: selectionAction(.archive), trash: selectionAction(.trash),
            lock: { Task { await onLock() } }
        )
    }

    private func newItem() { sheet = .item(destination) }

    private func openSearch() {
        if destination == .generator { destination = .all }
        searchPresented = true
        searchFocused = true
    }

    private func selectionAction(_ action: ItemChange) -> (() -> Void)? {
        guard listModel.canPresentCounts, !changing, !destination.isHiddenCollection, let selectedCipher else { return nil }
        return { change(selectedCipher, action: action) }
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
            let message: String
            switch pending {
            case .item(let id):
                let count = try await TrashRemovalBatch(ids: [id]).perform { try await vault.permanentlyDeleteCipher(id: $0) }
                message = TrashRemovalBatch.receipt(for: count)
            case .empty(let removal):
                let count = try await removal.perform { try await vault.permanentlyDeleteCipher(id: $0) }
                message = TrashRemovalBatch.receipt(for: count)
            case .folder(let id, _):
                try await vault.deleteFolder(id: id)
                if destination == .folder(id) { destination = .unfiled }
                message = "已删除文件夹"
            }
            feedback = OperationFeedback(message: message)
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
            catch let incomplete as TrashRemovalBatch.Failure { failure = incomplete.message }
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

    private func retryRead() {
        Task { await reloadVault() }
    }

    private func reloadVault() async {
        await listModel.load()
        guard !Task.isCancelled, !listModel.isLoading else { return }
        guard listModel.hasLoadedContent else {
            entries = []
            selectedID = nil
            observedSends = nil
            return
        }
        entries = MacTOTPEntry.entries(from: listModel.items)
        if let id = destination.folderID, !listModel.folders.contains(where: { $0.id == id }) {
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

private enum WorkspaceSheet: Identifiable {
    case item(MacDestination), edit(PlaintextCipher), transfer(VaultTransferMode)

    var id: String {
        switch self {
        case .item: "new"
        case .edit(let cipher): "edit-\(cipher.macStableID)"
        case .transfer(.importItems): "import"
        case .transfer(.exportItems): "export"
        }
    }
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
    case item(id: String), empty(TrashRemovalBatch), folder(id: String, count: Int)

    var title: String {
        switch self {
        case .item: "永久删除这个条目？"
        case .empty(let removal): "永久删除回收站中的 \(removal.ids.count) 个条目？"
        case .folder: "删除这个文件夹？"
        }
    }

    var message: String {
        switch self {
        case .folder(_, let count): "其中 \(count) 个条目将移到“无文件夹”，条目不会被删除。"
        case .item, .empty: TrashRemovalBatch.confirmationMessage
        }
    }

    var buttonTitle: String {
        switch self {
        case .folder: "删除文件夹"
        case .item, .empty: "永久删除"
        }
    }
}
