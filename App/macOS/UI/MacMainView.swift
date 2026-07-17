import SwiftUI
import UIShared
import DesignSystem
import VaultRepository

@available(macOS 27.0, *)
public struct MacMainView: View {
    private let auth: AuthService
    private let vault: VaultService
    private let settings: SettingsModel
    private let dataRevision: UInt64
    private let onAuthChange: () async -> Void

    @State private var listModel: VaultListModel
    @State private var syncModel: SyncStatusModel
    @State private var destination: MacDestination = .all
    @State private var selectedItemID: String?
    @State private var selectedTOTPItemID: String?
    @State private var searchText = ""
    @State private var showingNewItem = false
    @State private var columnVisibility: NavigationSplitViewVisibility = .all
    @FocusState private var searchFocused: Bool

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

    private var authenticatorEntries: [MacTOTPEntry] {
        MacTOTPEntry.entries(from: listModel.items)
    }

    private var counts: MacSidebarCounts {
        MacSidebarCounts(items: listModel.items, authenticators: authenticatorEntries)
    }

    private var visibleItems: [PlaintextCipher] {
        guard destination.isVaultFilter else { return [] }
        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines)
        return listModel.items.filter { cipher in
            destination.matches(cipher) && (query.isEmpty || cipher.matchesMacSearch(query))
        }
    }

    private var visibleAuthenticators: [MacTOTPEntry] {
        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !query.isEmpty else { return authenticatorEntries }
        return authenticatorEntries.filter {
            $0.cipher.name.localizedCaseInsensitiveContains(query)
                || $0.account.localizedCaseInsensitiveContains(query)
                || ($0.website?.localizedCaseInsensitiveContains(query) ?? false)
        }
    }

    private var selectedCipher: PlaintextCipher? {
        guard let selectedItemID else { return nil }
        return listModel.items.first { $0.macStableID == selectedItemID }
    }

    private var selectedAuthenticator: MacTOTPEntry? {
        guard let selectedTOTPItemID else { return nil }
        return authenticatorEntries.first { $0.id == selectedTOTPItemID }
    }

    public var body: some View {
        NavigationSplitView(columnVisibility: $columnVisibility) {
            MacSidebarView(
                selection: $destination,
                searchText: $searchText,
                searchFocus: $searchFocused,
                counts: counts,
                syncModel: syncModel,
                onSync: sync
            )
            .navigationSplitViewColumnWidth(min: 230, ideal: 250, max: 280)
        } content: {
            contentColumn
                .navigationSplitViewColumnWidth(min: 280, ideal: 308, max: 390)
        } detail: {
            detailColumn
        }
        .navigationSplitViewStyle(.balanced)
        .background(MacOpenVaultStyle.window)
        .sheet(isPresented: $showingNewItem) {
            MacItemEditView(vault: vault) { newID in
                showingNewItem = false
                destination = .all
                Task {
                    await listModel.load()
                    selectedItemID = newID
                }
            }
        }
        .task {
            await listModel.load()
            normalizeSelection()
            _ = await syncModel.sync()
            normalizeSelection()
        }
        .onChange(of: destination) { _, _ in normalizeSelection() }
        .onChange(of: searchText) { _, _ in normalizeSelection() }
        .onChange(of: dataRevision) { _, _ in
            Task {
                await listModel.reloadCurrentView()
                normalizeSelection()
            }
        }
        .background {
            Button("搜索保险库") {
                searchFocused = true
            }
            .keyboardShortcut("k", modifiers: .command)
            .frame(width: 0, height: 0)
            .opacity(0)
            .accessibilityHidden(true)
        }
    }

    @ViewBuilder
    private var contentColumn: some View {
        switch destination {
        case .authenticator:
            MacAuthenticatorListView(
                entries: visibleAuthenticators,
                selection: $selectedTOTPItemID,
                onNewItem: { showingNewItem = true }
            )
        case .security, .generator, .send, .settings:
            MacToolColumnView(destination: destination)
        default:
            MacItemListView(
                title: destination.title,
                items: visibleItems,
                isLoading: listModel.isLoading,
                errorMessage: listModel.errorMessage,
                selection: $selectedItemID,
                onNewItem: { showingNewItem = true }
            )
        }
    }

    @ViewBuilder
    private var detailColumn: some View {
        switch destination {
        case .authenticator:
            if let entry = selectedAuthenticator {
                MacAuthenticatorDetailView(entry: entry) {
                    selectedItemID = entry.cipher.macStableID
                    destination = .all
                }
                .id(entry.id)
            } else {
                unavailableSelection(title: "选择验证码", icon: "clock",
                                     description: "从列表中选择一个账户以查看动态验证码。")
            }
        case .generator:
            MacGeneratorView()
        case .send:
            MacSendView()
        case .security:
            MacSecurityView()
        case .settings:
            MacSettingsView(auth: auth, syncModel: syncModel, settings: settings,
                            onSync: reloadVault,
                            onAuthChange: onAuthChange)
        default:
            if let cipher = selectedCipher {
                MacItemDetailView(cipher: cipher, vault: vault) {
                    Task { await reloadVault() }
                }
                .id(cipher.macStableID)
            } else {
                unavailableSelection(title: "未选择条目", icon: "lock.shield",
                                     description: "从列表中选择一个条目以查看详情。")
            }
        }
    }

    private func unavailableSelection(title: String, icon: String, description: String) -> some View {
        ContentUnavailableView(title, systemImage: icon, description: Text(description))
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(MacOpenVaultStyle.detail)
    }

    private func normalizeSelection() {
        if destination == .authenticator {
            if !visibleAuthenticators.contains(where: { $0.id == selectedTOTPItemID }) {
                selectedTOTPItemID = visibleAuthenticators.first?.id
            }
        } else if destination.isVaultFilter {
            if !visibleItems.contains(where: { $0.macStableID == selectedItemID }) {
                selectedItemID = visibleItems.first?.macStableID
            }
        }
    }

    private func sync() {
        Task {
            _ = await syncModel.sync()
            normalizeSelection()
        }
    }

    private func reloadVault() async {
        await listModel.load()
        normalizeSelection()
    }
}

private extension PlaintextCipher {
    func matchesMacSearch(_ query: String) -> Bool {
        if name.localizedCaseInsensitiveContains(query) { return true }
        if notes?.localizedCaseInsensitiveContains(query) == true { return true }
        if login?.username?.localizedCaseInsensitiveContains(query) == true { return true }
        return login?.uris.contains { $0.uri.localizedCaseInsensitiveContains(query) } == true
    }
}
