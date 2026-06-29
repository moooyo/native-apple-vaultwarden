// Xcode-only target (UI-iOS / UI-mac). Not part of the SPM build.
//
// MainTabView — the signed-in iOS shell. A `TabView` with Vault / Generator / Send /
// Settings tabs, a search tab (`Tab(role: .search)`) feeding bottom `searchable`, a
// `.tabViewBottomAccessory` showing the sync pill, and `.tabBarMinimizeBehavior`.
//
// Liquid Glass notes:
//   * The tab bar + bottom accessory get the system material automatically.
//   * The floating "+" is a genuinely custom chrome surface, so it uses
//     `.buttonStyle(.glassProminent)` and lives inside a `GlassEffectContainer` (so
//     additional floating buttons blend/morph as one glass shape).

import SwiftUI
import UIShared
import DesignSystem
import VaultRepository

@available(iOS 26.0, *)
public struct MainTabView: View {
    private let auth: AuthService
    private let vault: VaultService
    private let settings: SettingsModel
    /// Asks the root to re-evaluate auth (after lock / logout from Settings).
    private let onAuthChange: () async -> Void

    // One owned model per long-lived screen.
    @State private var listModel: VaultListModel
    @State private var syncModel: SyncStatusModel

    @State private var selection: TabIdentifier = .vault
    @State private var searchText = ""
    /// Drives the create-item sheet from the floating "+".
    @State private var showingNewItem = false

    @Namespace private var glassNamespace

    enum TabIdentifier: Hashable { case vault, generator, send, settings, search }

    public init(auth: AuthService, vault: VaultService, settings: SettingsModel,
                onAuthChange: @escaping () async -> Void) {
        self.auth = auth
        self.vault = vault
        self.settings = settings
        self.onAuthChange = onAuthChange
        _listModel = State(initialValue: VaultListModel(vault: vault))
        _syncModel = State(initialValue: SyncStatusModel(vault: vault))
    }

    public var body: some View {
        TabView(selection: $selection) {
            Tab("Vault", systemImage: "lock.shield", value: TabIdentifier.vault) {
                NavigationStack {
                    VaultListView(model: listModel, vault: vault)
                }
            }

            Tab("Generator", systemImage: "wand.and.stars", value: TabIdentifier.generator) {
                NavigationStack {
                    GeneratorView()
                }
            }

            Tab("Send", systemImage: "paperplane", value: TabIdentifier.send) {
                NavigationStack {
                    SendPlaceholderView()
                }
            }

            Tab("Settings", systemImage: "gearshape", value: TabIdentifier.settings) {
                NavigationStack {
                    SettingsView(auth: auth, syncModel: syncModel, settings: settings,
                                 onAuthChange: onAuthChange)
                }
            }

            // The search tab routes to the bottom search field on iPhone.
            Tab(value: TabIdentifier.search, role: .search) {
                NavigationStack {
                    VaultListView(model: listModel, vault: vault)
                }
            }
        }
        // Search field; binds the list model's query and debounce-searches on change.
        .searchable(text: $searchText, placement: .toolbar, prompt: "Search vault")
        .onChange(of: searchText) { _, newValue in
            Task {
                // Lightweight debounce so we don't hit the store on every keystroke.
                try? await Task.sleep(for: .milliseconds(250))
                guard newValue == searchText else { return }
                await listModel.search(newValue)
            }
        }
        .tabBarMinimizeBehavior(.onScrollDown)
        .tabViewBottomAccessory {
            SyncStatusPill(model: syncModel)
        }
        // Floating "+" overlay — only meaningful on the Vault/search tabs.
        .overlay(alignment: .bottomTrailing) {
            if selection == .vault || selection == .search {
                FloatingAddButton(namespace: glassNamespace) {
                    showingNewItem = true
                }
                .padding(.trailing, Spacing.lg)
                .padding(.bottom, Spacing.xxl)
            }
        }
        .sheet(isPresented: $showingNewItem) {
            NavigationStack {
                ItemEditView(vault: vault) { _ in
                    showingNewItem = false
                    Task { await listModel.load() }
                }
            }
        }
        .task {
            await listModel.load()
            await syncModel.sync()
        }
    }
}

// MARK: - Floating add button (custom glass chrome)

@available(iOS 26.0, *)
private struct FloatingAddButton: View {
    let namespace: Namespace.ID
    let action: () -> Void

    var body: some View {
        // Wrapping in a container so any additional floating buttons (e.g. a future
        // quick-scan) blend into one morphing glass shape.
        GlassEffectContainer(spacing: Spacing.md) {
            Button(action: action) {
                Image(systemName: "plus")
                    .font(.title2.weight(.semibold))
                    .frame(width: 28, height: 28)
            }
            .buttonStyle(.glassProminent)
            .glassEffectID("add-item", in: namespace)
            .accessibilityLabel("Add item")
        }
    }
}

// MARK: - Sync pill for the tab-bar bottom accessory

@available(iOS 26.0, *)
private struct SyncStatusPill: View {
    let model: SyncStatusModel

    var body: some View {
        HStack(spacing: Spacing.sm) {
            if model.isSyncing {
                ProgressView().controlSize(.small)
                Text("Syncing…")
            } else if let message = model.errorMessage {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(Palette.warning)
                Text(message).lineLimit(1)
            } else if let last = model.lastSync {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundStyle(Palette.success)
                Text("Synced \(last.formatted(.relative(presentation: .named)))")
                    .lineLimit(1)
            } else {
                Image(systemName: "arrow.triangle.2.circlepath")
                Text("Not yet synced")
            }
            Spacer(minLength: 0)
        }
        .font(Typography.rowSubtitle)
        .foregroundStyle(Palette.secondaryText)
        .padding(.horizontal, Spacing.md)
        .frame(maxWidth: .infinity)
        .contentShape(Rectangle())
        .onTapGesture { Task { await model.sync() } }
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isButton)
        .accessibilityHint("Tap to sync now")
    }
}

// MARK: - Send placeholder (M2)

@available(iOS 26.0, *)
private struct SendPlaceholderView: View {
    var body: some View {
        ContentUnavailableView(
            "Send",
            systemImage: "paperplane",
            description: Text("Bitwarden Send arrives in a later release.")
        )
        .navigationTitle("Send")
    }
}
