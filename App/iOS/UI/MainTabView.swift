import SwiftUI
import DesignSystem
import UIShared
import VaultRepository

@available(iOS 27.0, *)
enum NavigationTab: Hashable {
    case vault, codes, send, generator, search
    case filter(VaultWorkspaceSection), folder(String?), archive, trash
}

@available(iOS 27.0, *)
public struct MainTabView: View {
    private let auth: AuthService
    private let vault: VaultService
    private let settings: SettingsModel
    private let dataRevision: UInt64
    private let onAuthChange: () async -> Void

    @Environment(\.horizontalSizeClass) private var sizeClass
    @State private var listModel: VaultListModel
    @State private var searchModel: VaultListModel
    @State private var syncModel: SyncStatusModel
    @State private var generatorModel: GeneratorModel
    @State private var selection: NavigationTab = .vault
    @State private var searchText = ""
    @State private var padSearchSource: NavigationTab?
    @State private var settingsSource: NavigationTab?
    @State private var creating: Creation?
    @State private var selectedItemID: String?
    @State private var padScope = PadVaultScope.all
    @State private var sort = VaultSortOrder.name
    @State private var creatingFolder = false
    @State private var folderName = ""
    @State private var folderError = false
    @State private var writingFolder = false

    private struct Creation: Identifiable {
        let id = UUID()
        var folderID: String?
        var requiresCode = false
    }

    public init(auth: AuthService, vault: VaultService, settings: SettingsModel,
                dataRevision: UInt64 = 0, onAuthChange: @escaping () async -> Void) {
        self.auth = auth
        self.vault = vault
        self.settings = settings
        self.dataRevision = dataRevision
        self.onAuthChange = onAuthChange
        let list = VaultListModel(vault: vault)
        let search = VaultListModel(vault: vault)
        _listModel = State(initialValue: list)
        _searchModel = State(initialValue: search)
        _syncModel = State(initialValue: SyncStatusModel(vault: vault, onSuccess: {
            await list.reloadCurrentView()
            await search.reloadCurrentView()
        }))
        _generatorModel = State(initialValue: GeneratorModel(vault: vault))
    }

    private var regular: Bool { sizeClass == .regular }

    public var body: some View {
        Group {
            if regular {
                tabs
            } else {
                tabs
                    .searchable(text: $searchText, prompt: "搜索保险库")
                    .tabViewSearchActivation(.searchTabSelection)
            }
        }
        .sheet(item: $creating) { request in
            NavigationStack {
                ItemEditView(vault: vault, initialFolderID: request.folderID, requiresCode: request.requiresCode) { id in
                    creating = nil
                    Task {
                        await reload()
                        selectedItemID = id
                    }
                }
            }
            .presentationSizing(.form)
            .presentationDragIndicator(.visible)
        }
        .alert("新建文件夹", isPresented: $creatingFolder) {
            TextField("名称", text: $folderName)
            Button("取消", role: .cancel) {}
            Button("创建", action: createFolder)
                .disabled(folderName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        }
        .alert("未能新建文件夹", isPresented: $folderError) {
            Button("好", role: .cancel) {}
        } message: { Text("请刷新保险库后重试。") }
        .task {
            await listModel.load()
            guard !Task.isCancelled else { return }
            if syncModel.lastSync == nil { _ = await syncModel.sync() }
        }
        .task(id: dataRevision) {
            if dataRevision != 0 { await reload() }
        }
        .onChange(of: regular) { _, wide in
            if wide {
                if selection == .search {
                    selection = .vault
                    padSearchSource = .vault
                }
            } else {
                if padSearchSource != nil {
                    padSearchSource = nil
                    selection = .search
                    return
                }
                switch selection {
                case .filter, .folder, .archive, .trash:
                    if settingsSource == selection { settingsSource = .vault }
                    selection = .vault
                default: break
                }
            }
        }
        .onChange(of: listModel.folders) { _, folders in
            guard listModel.errorMessage == nil else { return }
            if case let .folder(id?) = padScope, !folders.contains(where: { $0.id == id }) { padScope = .folder(nil) }
            if case let .folder(id?) = selection, !folders.contains(where: { $0.id == id }) { navigate(to: .folder(nil)) }
        }
    }

    private var tabs: some View {
        let folderCounts = regular ? listModel.items.reduce(into: [String?: Int]()) { $0[$1.folderID, default: 0] += 1 } : [:]
        return TabView(selection: Binding(get: { selection }, set: { navigate(to: $0) })) {
            Tab("保险库", systemImage: "lock.shield.fill", value: NavigationTab.vault) {
                page(.vault) {
                    if regular {
                        columns(padScope, tab: .vault)
                    } else {
                        toolStack(.vault) {
                            VaultListView(model: listModel, vault: vault, onAdd: { creating = Creation() },
                                          onOpenSettings: { settingsSource = .vault })
                        }
                    }
                }
            }
            Tab(value: NavigationTab.codes) {
                page(.codes) {
                    toolStack(.codes) {
                        CodesView(model: listModel, vault: vault, onAdd: { creating = Creation(requiresCode: true) })
                    }
                }
            } label: { Label("验证码", systemImage: "clock.fill").accessibilityIdentifier("tab.codes") }
            Tab("Send", systemImage: "paperplane.fill", value: NavigationTab.send) {
                page(.send) {
                    toolStack(.send) { OpenVaultSendView(vault: vault, dataRevision: dataRevision) }
                }
            }
            Tab(value: NavigationTab.generator) {
                page(.generator) { toolStack(.generator) { GeneratorView(model: generatorModel) } }
            } label: { Label("生成器", systemImage: "wand.and.stars").accessibilityIdentifier("tab.generator") }
            if regular {
                TabSection("类型") {
                    ForEach(VaultWorkspaceSection.itemTypes.filter { $0 != .codes }) { section in
                        Tab(section.title, systemImage: section.systemImage, value: NavigationTab.filter(section)) {
                            page(.filter(section)) { columns(.type(section), tab: .filter(section)) }
                        }
                        .badge(listModel.items.count(where: { $0.isIncluded(in: section) }))
                        .tabPlacement(.sidebarOnly)
                    }
                }
                TabSection("文件夹") {
                    ForEach(listModel.folders) { folder in
                        Tab(folder.name, systemImage: "folder", value: NavigationTab.folder(folder.id)) {
                            page(.folder(folder.id)) { columns(.folder(folder.id), tab: .folder(folder.id)) }
                        }
                        .badge(folderCounts[folder.id, default: 0])
                        .tabPlacement(.sidebarOnly)
                    }
                    Tab("无文件夹", systemImage: "tray", value: NavigationTab.folder(nil)) {
                        page(.folder(nil)) { columns(.folder(nil), tab: .folder(nil)) }
                    }
                    .badge(folderCounts[nil, default: 0])
                    .tabPlacement(.sidebarOnly)
                }
                .sectionActions {
                    Button("新建文件夹", systemImage: "plus") { folderName = ""; creatingFolder = true }
                        .disabled(writingFolder)
                }
                TabSection("隐藏的条目") {
                    Tab("归档", systemImage: "archivebox", value: NavigationTab.archive) {
                        page(.archive) { columns(.archive, tab: .archive) }
                    }
                    .badge(listModel.archivedItems.count)
                    .tabPlacement(.sidebarOnly)
                    Tab("回收站", systemImage: "trash", value: NavigationTab.trash) {
                        page(.trash) { columns(.trash, tab: .trash) }
                    }
                    .badge(listModel.trashedItems.count)
                    .tabPlacement(.sidebarOnly)
                }
            } else {
                Tab(value: NavigationTab.search, role: .search) {
                    NavigationStack { searchPage }
                        .vaultOperationFeedback()
                }
            }
        }
        .tabViewStyle(.sidebarAdaptable)
        .tabViewSidebarBottomBar {
            if regular {
                Button(action: openPadSettings) {
                    Label("设置", systemImage: "gearshape")
                        .frame(maxWidth: .infinity, minHeight: LayoutMetric.minimumTapTarget, alignment: .leading)
                        .padding(.horizontal, Spacing.lg)
                        .contentShape(Rectangle())
                }
                    .accessibilityIdentifier("navigation.settings")
            }
        }
        .tabBarMinimizeBehavior(.onScrollDown)
    }

    private func page<Content: View>(_ tab: NavigationTab, @ViewBuilder content: () -> Content) -> some View {
        let searching = regular && padSearchSource == tab
        let showingSettings = regular && settingsSource == tab
        return ZStack {
            ZStack {
                content()
                    .opacity(showingSettings ? 0 : 1)
                    .disabled(showingSettings)
                    .accessibilityHidden(showingSettings)
                if showingSettings {
                    settingsPage.safeAreaInset(edge: .top, alignment: .leading, spacing: 0) {
                        Button("返回", systemImage: "chevron.backward") { settingsSource = nil }
                            .labelStyle(.iconOnly)
                            .buttonStyle(.glass)
                            .buttonBorderShape(.circle)
                            .controlSize(.large)
                            .padding(.leading, Spacing.lg)
                            .accessibilityIdentifier("settings.back")
                    }
                }
            }
            .safeAreaInset(edge: .bottom, alignment: .trailing, spacing: 0) {
                if regular {
                    Button("搜索保险库", systemImage: "magnifyingglass") {
                        searchText = ""
                        padSearchSource = tab
                    }
                    .labelStyle(.iconOnly)
                    .buttonStyle(.glass)
                    .buttonBorderShape(.circle)
                    .controlSize(.large)
                    .keyboardShortcut("f", modifiers: .command)
                    .accessibilityIdentifier("search.open")
                    .padding(.trailing, Spacing.lg)
                    .padding(.bottom, Spacing.sm)
                }
            }
            .opacity(searching ? 0 : 1)
            .disabled(searching)
            .accessibilityHidden(searching)
            if searching {
                NavigationStack {
                    searchPage
                        .safeAreaInset(edge: .bottom) {
                            PadSearchField(text: $searchText, onClose: closePadSearch)
                        }
                }
            }
        }
        .vaultOperationFeedback()
    }

    private func toolStack<Content: View>(_ tab: NavigationTab, @ViewBuilder content: () -> Content) -> some View {
        NavigationStack {
            content()
                .toolbar {
                    if regular || tab != .vault {
                        ToolbarItem(placement: .topBarTrailing) {
                            NavigationSettingsButton(regular: regular) { settingsSource = tab }
                        }
                    }
                }
                .navigationDestination(isPresented: Binding(get: { !regular && settingsSource == tab }, set: {
                    if !$0, !regular, settingsSource == tab { settingsSource = nil }
                })) { settingsPage }
        }
    }

    private func columns(_ scope: PadVaultScope, tab: NavigationTab) -> some View {
        PadVaultColumns(model: listModel, vault: vault, scope: scope, isActive: selection == tab,
                        selectedID: $selectedItemID, sort: $sort,
                        onAdd: { folderID in creating = Creation(folderID: folderID) },
                        onSettings: openPadSettings,
                        onSelectScope: { section in
                            padScope = section == .all ? .all : .type(section)
                            selection = .vault
                        }, onSidebarChange: { visible in
                            guard regular, tab == selection, padSearchSource == nil, settingsSource == nil else { return }
                            if visible, selection == .vault {
                                switch scope {
                                case let .type(section) where section != .favorites: selection = .filter(section)
                                case let .folder(id): selection = .folder(id)
                                case .archive: selection = .archive
                                case .trash: selection = .trash
                                default: break
                                }
                            } else if !visible, selection != .vault {
                                padScope = scope
                                selection = .vault
                            }
                        })
    }

    private var searchPage: some View {
        VaultSearchView(model: searchModel, vault: vault)
            .task(id: searchText) {
                let query = searchText
                if !query.isEmpty {
                    do { try await Task.sleep(for: .milliseconds(180)) } catch { return }
                }
                await searchModel.search(query)
            }
    }

    private var settingsPage: some View {
        SettingsView(auth: auth, vault: vault, model: listModel, syncModel: syncModel, settings: settings,
                     onSync: reload, onAuthChange: onAuthChange)
    }

    private func closePadSearch() {
        padSearchSource = nil
        searchText = ""
        Task { await listModel.load() }
    }

    private func openPadSettings() {
        if padSearchSource != nil { closePadSearch() }
        settingsSource = selection
    }

    private func navigate(to destination: NavigationTab) {
        if destination == .vault { padScope = .all }
        if selection == .search || padSearchSource != nil { Task { await listModel.load() } }
        padSearchSource = nil
        settingsSource = nil
        searchText = ""
        selection = destination
    }

    private func reload() async {
        await listModel.load()
        await searchModel.search(searchText)
    }

    private func createFolder() {
        let name = folderName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, !writingFolder else { return }
        writingFolder = true
        Task {
            defer { writingFolder = false }
            do {
                let id = try await vault.createFolder(name: name)
                await listModel.load()
                if regular, listModel.folders.contains(where: { $0.id == id }) { selection = .folder(id) }
            } catch { folderError = true }
        }
    }
}

private struct NavigationSettingsButton: View {
    let regular: Bool
    let action: () -> Void
    @Environment(\.tabBarPlacement) private var placement

    var body: some View {
        if !regular || placement != .sidebar {
            Button("设置", systemImage: "gearshape", action: action)
                .accessibilityIdentifier("navigation.settings")
        }
    }
}
