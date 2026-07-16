// Xcode-only target (UI-iOS / UI-mac). Not part of the SPM build.
//
// MacMainView — the signed-in macOS shell: a three-column `NavigationSplitView`
// (categories/folders sidebar | item list | detail). The list reuses `VaultListModel`
// from UIShared; selection drives the detail column.
//
// Liquid Glass: the split-view chrome (sidebar, toolbars) gets the material on recompile.
// The detail hero uses `.backgroundExtensionEffect()`; toolbars use `ToolbarSpacer` to
// split actions into separate glass capsules.

import SwiftUI
import UIShared
import DesignSystem
import VaultRepository
import VaultModels

@available(macOS 26.0, *)
public struct MacMainView: View {
    private let auth: AuthService
    private let vault: VaultService
    private let settings: SettingsModel
    private let dataRevision: UInt64
    private let onAuthChange: () async -> Void

    @State private var listModel: VaultListModel
    @State private var syncModel: SyncStatusModel

    @State private var selectedCategory: MacCategory = .all
    @State private var selectedItemID: String?
    @State private var searchText = ""
    @State private var showingNewItem = false
    @State private var showingSettings = false

    @State private var columnVisibility: NavigationSplitViewVisibility = .all

    public init(auth: AuthService, vault: VaultService, settings: SettingsModel,
                dataRevision: UInt64 = 0,
                onAuthChange: @escaping () async -> Void) {
        self.auth = auth
        self.vault = vault
        self.settings = settings
        self.dataRevision = dataRevision
        self.onAuthChange = onAuthChange
        let listModel = VaultListModel(vault: vault)
        _listModel = State(initialValue: listModel)
        _syncModel = State(initialValue: SyncStatusModel(
            vault: vault,
            onSuccess: { await listModel.reloadCurrentView() }
        ))
    }

    /// Items filtered by the selected sidebar category (search is applied in the model).
    private var filteredItems: [PlaintextCipher] {
        listModel.items.filter { selectedCategory.matches($0) }
    }

    private var selectedCipher: PlaintextCipher? {
        guard let id = selectedItemID else { return nil }
        return listModel.items.first { $0.id == id }
    }

    public var body: some View {
        NavigationSplitView(columnVisibility: $columnVisibility) {
            MacSidebarView(selection: $selectedCategory, syncModel: syncModel)
                .navigationSplitViewColumnWidth(min: 200, ideal: 220, max: 280)
        } content: {
            MacItemListView(items: filteredItems,
                            isLoading: listModel.isLoading,
                            selection: $selectedItemID)
                .navigationSplitViewColumnWidth(min: 260, ideal: 300, max: 420)
                .navigationTitle(selectedCategory.title)
        } detail: {
            if let cipher = selectedCipher {
                MacItemDetailView(cipher: cipher, vault: vault) {
                    Task { await listModel.load() }
                }
                .id(cipher.id) // rebuild detail state when selection changes
            } else {
                ContentUnavailableView("No Selection", systemImage: "lock.shield",
                                       description: Text("Select an item to view its details."))
            }
        }
        .searchable(text: $searchText, placement: .toolbar, prompt: "Search vault")
        .onChange(of: searchText) { _, newValue in
            Task {
                try? await Task.sleep(for: .milliseconds(250))
                guard newValue == searchText else { return }
                await listModel.search(newValue)
            }
        }
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                Button {
                    Task { await syncModel.sync() }
                } label: {
                    Label("Sync", systemImage: "arrow.triangle.2.circlepath")
                }
                .disabled(syncModel.isSyncing)
            }

            // Split actions into their own glass capsule.
            ToolbarSpacer(.flexible)

            ToolbarItemGroup(placement: .primaryAction) {
                Button {
                    showingNewItem = true
                } label: {
                    Label("New Item", systemImage: "plus")
                }
                Button {
                    showingSettings = true
                } label: {
                    Label("Settings", systemImage: "gearshape")
                }
            }
        }
        .sheet(isPresented: $showingNewItem) {
            MacItemEditView(vault: vault) { newID in
                showingNewItem = false
                Task {
                    await listModel.load()
                    selectedItemID = newID
                }
            }
        }
        .sheet(isPresented: $showingSettings) {
            MacSettingsView(auth: auth, syncModel: syncModel, settings: settings,
                            onAuthChange: onAuthChange)
        }
        .task {
            await listModel.load()
            await syncModel.sync()
        }
        .onChange(of: dataRevision) { _, _ in
            Task { await listModel.reloadCurrentView() }
        }
    }
}

// MARK: - Sidebar categories

@available(macOS 26.0, *)
enum MacCategory: Hashable, CaseIterable {
    case all, favorites, login, secureNote, card, identity, sshKey

    var title: String {
        switch self {
        case .all: return "All Items"
        case .favorites: return "Favorites"
        case .login: return "Logins"
        case .secureNote: return "Secure Notes"
        case .card: return "Cards"
        case .identity: return "Identities"
        case .sshKey: return "SSH Keys"
        }
    }

    var systemImage: String {
        switch self {
        case .all: return "tray.full"
        case .favorites: return "star"
        case .login: return "person.crop.circle"
        case .secureNote: return "note.text"
        case .card: return "creditcard"
        case .identity: return "person.text.rectangle"
        case .sshKey: return "key.horizontal"
        }
    }

    func matches(_ cipher: PlaintextCipher) -> Bool {
        switch self {
        case .all: return true
        case .favorites: return cipher.favorite
        case .login: return cipher.type == CipherType.login.rawValue
        case .secureNote: return cipher.type == CipherType.secureNote.rawValue
        case .card: return cipher.type == CipherType.card.rawValue
        case .identity: return cipher.type == CipherType.identity.rawValue
        case .sshKey: return cipher.type == CipherType.sshKey.rawValue
        }
    }
}
