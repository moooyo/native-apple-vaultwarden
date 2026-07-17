import SwiftUI
import UIShared
import DesignSystem

@available(iOS 27.0, *)
public struct MainTabView: View {
    private let auth: AuthService
    private let vault: VaultService
    private let settings: SettingsModel
    private let dataRevision: UInt64
    private let onAuthChange: () async -> Void

    @Environment(\.horizontalSizeClass) private var horizontalSizeClass

    @State private var listModel: VaultListModel
    @State private var searchModel: VaultListModel
    @State private var syncModel: SyncStatusModel
    @State private var selection: OpenVaultTab = .vault
    @State private var searchText = ""
    @State private var showingNewItem = false
    @AppStorage(OpenVaultPreferenceKey.glassTint) private var glassTint = 0.68
    @AppStorage(OpenVaultPreferenceKey.theme) private var themeRawValue = OpenVaultTheme.system.rawValue

    public init(auth: AuthService, vault: VaultService, settings: SettingsModel,
                dataRevision: UInt64 = 0,
                onAuthChange: @escaping () async -> Void) {
        self.auth = auth
        self.vault = vault
        self.settings = settings
        self.dataRevision = dataRevision
        self.onAuthChange = onAuthChange
        let listModel = VaultListModel(vault: vault)
        let searchModel = VaultListModel(vault: vault)
        _listModel = State(initialValue: listModel)
        _searchModel = State(initialValue: searchModel)
        _syncModel = State(initialValue: SyncStatusModel(
            vault: vault,
            onSuccess: {
                await listModel.reloadCurrentView()
                await searchModel.reloadCurrentView()
            }
        ))
    }

    public var body: some View {
        Group {
            if horizontalSizeClass == .regular {
                OpenVaultPadWorkspace(
                    auth: auth,
                    vault: vault,
                    settings: settings,
                    listModel: listModel,
                    syncModel: syncModel,
                    onAdd: { showingNewItem = true },
                    onAuthChange: onAuthChange
                )
            } else {
                phoneTabs
            }
        }
        .openVaultGlassTint(glassTint)
        .preferredColorScheme(OpenVaultTheme(rawValue: themeRawValue)?.colorScheme)
        .sheet(isPresented: $showingNewItem) {
            NavigationStack {
                ItemEditView(vault: vault) { _ in
                    showingNewItem = false
                    Task {
                        await listModel.load()
                        await searchModel.search(searchText)
                    }
                }
            }
            .presentationDetents([.large])
            .presentationDragIndicator(.visible)
        }
        .task {
            if listModel.items.isEmpty { await listModel.load() }
            if searchModel.items.isEmpty { await searchModel.load() }
            if syncModel.lastSync == nil, await syncModel.sync() {
                await listModel.load()
                await searchModel.search(searchText)
            }
        }
        .onChange(of: dataRevision) { _, _ in
            Task {
                await listModel.reloadCurrentView()
                await searchModel.reloadCurrentView()
            }
        }
    }

    private var phoneTabs: some View {
        TabView(selection: $selection) {
            Tab("保险库", systemImage: "lock.shield", value: OpenVaultTab.vault) {
                NavigationStack {
                    VaultListView(
                        model: listModel,
                        vault: vault,
                        onAdd: { showingNewItem = true },
                        onOpenCodes: { selection = .codes },
                        onOpenSettings: { selection = .settings }
                    )
                }
            }

            Tab("验证码", systemImage: "clock", value: OpenVaultTab.codes) {
                NavigationStack {
                    CodesView(model: listModel, vault: vault,
                              onAdd: { showingNewItem = true })
                }
            }

            Tab("生成器", systemImage: "sparkles", value: OpenVaultTab.generator) {
                NavigationStack { GeneratorView() }
            }

            Tab("发送", systemImage: "paperplane", value: OpenVaultTab.send) {
                NavigationStack { OpenVaultSendView() }
            }

            Tab("设置", systemImage: "gearshape", value: OpenVaultTab.settings) {
                NavigationStack {
                    SettingsView(auth: auth, syncModel: syncModel, settings: settings,
                                 onSync: {
                                     await listModel.load()
                                     await searchModel.search(searchText)
                                 },
                                 onAuthChange: onAuthChange)
                }
            }

            Tab(value: OpenVaultTab.search, role: .search) {
                NavigationStack {
                    VaultSearchView(model: searchModel, vault: vault,
                                    onAdd: { showingNewItem = true })
                }
            }
        }
        .searchable(text: $searchText, prompt: "搜索保险库")
        .tabViewSearchActivation(.searchTabSelection)
        .searchToolbarBehavior(.minimize)
        .tabBarMinimizeBehavior(.onScrollDown)
        .task(id: searchText) {
            try? await Task.sleep(for: .milliseconds(220))
            guard !Task.isCancelled else { return }
            await searchModel.search(searchText)
        }
    }
}
