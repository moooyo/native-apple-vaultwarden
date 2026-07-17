import SwiftUI
import UIShared
import DesignSystem
import VaultRepository
import VaultModels

@available(iOS 27.0, *)
struct OpenVaultPadWorkspace: View {
    let auth: AuthService
    let vault: VaultService
    let settings: SettingsModel
    @State var listModel: VaultListModel
    @State var syncModel: SyncStatusModel
    let onAdd: () -> Void
    let onAuthChange: () async -> Void

    @State private var columnVisibility: NavigationSplitViewVisibility = .all
    @State private var selectedSection: VaultWorkspaceSection = .all
    @State private var selectedID: String?
    @State private var query = ""
    @State private var operationError: String?
    @AppStorage(OpenVaultPreferenceKey.glassTint) private var glassTint = 0.68
    @AppStorage(OpenVaultPreferenceKey.theme) private var themeRawValue = OpenVaultTheme.system.rawValue

    private var filteredItems: [PlaintextCipher] {
        let sectionItems = listModel.items.filter { $0.isIncluded(in: selectedSection) }
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !needle.isEmpty else { return sectionItems }
        return sectionItems.filter { cipher in
            let fields = [cipher.name, cipher.login?.username]
                + (cipher.login?.uris.map(\.uri) ?? [])
            return fields.compactMap { $0 }.contains { $0.lowercased().contains(needle) }
        }
    }

    private var selectedCipher: PlaintextCipher? {
        guard let selectedID else { return nil }
        return listModel.items.first { $0.openVaultID == selectedID }
    }

    var body: some View {
        NavigationSplitView(columnVisibility: $columnVisibility) {
            sidebar
                .navigationSplitViewColumnWidth(min: 250, ideal: 280, max: 310)
        } content: {
            itemColumn
                .navigationSplitViewColumnWidth(min: 300, ideal: 330, max: 400)
        } detail: {
            detailColumn
        }
        .navigationSplitViewStyle(.balanced)
        .background(Palette.groupedBackground)
        .openVaultGlassTint(glassTint)
        .preferredColorScheme(OpenVaultTheme(rawValue: themeRawValue)?.colorScheme)
        .task {
            if listModel.items.isEmpty { await listModel.load() }
            normalizeSelection()
        }
        .onChange(of: selectedSection) { _, _ in
            query = ""
            normalizeSelection()
        }
        .onChange(of: query) { _, _ in normalizeSelection() }
        .onChange(of: listModel.items) { _, _ in normalizeSelection() }
        .alert("无法删除条目", isPresented: hasOperationError) {
            Button("好", role: .cancel) { operationError = nil }
        } message: {
            Text(operationError ?? "请稍后再试。")
        }
    }

    private var sidebar: some View {
        List {
            Section("过滤器") {
                sidebarRow(.all, count: listModel.items.count)
                sidebarRow(.favorites, count: listModel.items.filter(\.favorite).count)
                sidebarRow(.codes, count: listModel.items.filter {
                    $0.openVaultTOTPConfiguration != nil
                }.count)
            }

            Section("类型") {
                sidebarRow(.logins, count: count(.login))
                sidebarRow(.cards, count: count(.card))
                sidebarRow(.identities, count: count(.identity))
                sidebarRow(.secureNotes, count: count(.secureNote))
            }

            Section("工具") {
                sidebarRow(.generator)
                sidebarRow(.send)
                sidebarRow(.settings)
            }
        }
        .listStyle(.sidebar)
        .navigationTitle("保险库")
        .safeAreaInset(edge: .bottom) {
            HStack(spacing: Spacing.md) {
                Circle()
                    .fill(Palette.controlFill)
                    .frame(width: 34, height: 34)
                    .overlay { Text("O").font(.subheadline.weight(.semibold)) }
                VStack(alignment: .leading, spacing: 1) {
                    Text("OpenVault").font(.subheadline.weight(.semibold))
                    Text(syncStatusText)
                        .font(.caption)
                        .foregroundStyle(Palette.secondaryText)
                }
                Spacer()
                Button {
                    Task { await syncModel.sync(); await listModel.load() }
                } label: {
                    if syncModel.isSyncing {
                        ProgressView().controlSize(.small)
                    } else {
                        Image(systemName: "arrow.triangle.2.circlepath")
                    }
                }
                .buttonStyle(.plain)
                .accessibilityLabel("立即同步")
            }
            .padding(Spacing.md)
            .background(.bar)
        }
    }

    @ViewBuilder
    private func sidebarRow(_ section: VaultWorkspaceSection, count: Int? = nil) -> some View {
        Button {
            selectedSection = section
        } label: {
            HStack {
                Label(section.title, systemImage: section.systemImage)
                Spacer()
                if let count {
                    Text(count, format: .number)
                        .font(.caption)
                        .monospacedDigit()
                        .foregroundStyle(Palette.secondaryText)
                }
            }
        }
        .buttonStyle(.plain)
        .foregroundStyle(selectedSection == section ? Palette.accent : Palette.primaryText)
        .listRowBackground(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(selectedSection == section ? Palette.accent.opacity(0.14) : .clear)
        )
    }

    private var itemColumn: some View {
        Group {
            if selectedSection.isTool {
                ContentUnavailableView(selectedSection.title,
                                       systemImage: selectedSection.systemImage,
                                       description: Text("在右侧使用此工具。"))
            } else if filteredItems.isEmpty, !listModel.isLoading {
                ContentUnavailableView("没有条目", systemImage: "tray")
            } else if selectedSection == .codes {
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    List(filteredItems, id: \.openVaultID) { cipher in
                        Button { selectedID = cipher.openVaultID } label: {
                            VaultItemRow(cipher: cipher, date: context.date,
                                         showsFavorite: false, compactCode: true)
                        }
                        .buttonStyle(.plain)
                        .listRowBackground(selectedID == cipher.openVaultID
                                           ? Palette.accent.opacity(0.1) : Color.clear)
                    }
                    .listStyle(.inset)
                }
            } else {
                List(filteredItems, id: \.openVaultID) { cipher in
                    Button { selectedID = cipher.openVaultID } label: {
                        VaultItemRow(cipher: cipher)
                    }
                    .buttonStyle(.plain)
                    .listRowBackground(selectedID == cipher.openVaultID
                                       ? Palette.accent.opacity(0.1) : Color.clear)
                        .swipeActions(edge: .trailing, allowsFullSwipe: true) {
                            Button(role: .destructive) { delete(cipher) } label: {
                                Label("删除", systemImage: "trash")
                            }
                        }
                }
                .listStyle(.inset)
            }
        }
        .navigationTitle(selectedSection.title)
        .searchable(text: $query, prompt: "搜索")
        .toolbar {
            ToolbarItemGroup(placement: .topBarTrailing) {
                Button { Task { await listModel.refresh() } } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .disabled(listModel.isLoading)
                .accessibilityLabel("刷新")
                Button(action: onAdd) { Image(systemName: "plus") }
                    .accessibilityLabel("新建条目")
            }
        }
        .overlay { if listModel.isLoading, listModel.items.isEmpty { ProgressView() } }
    }

    @ViewBuilder
    private var detailColumn: some View {
        switch selectedSection {
        case .generator:
            NavigationStack { GeneratorView() }
        case .send:
            NavigationStack { OpenVaultSendView() }
        case .settings:
            NavigationStack {
                SettingsView(auth: auth, syncModel: syncModel, settings: settings,
                             onSync: { await listModel.load() },
                             onAuthChange: onAuthChange)
            }
        case .codes:
            if let selectedCipher {
                PadCodeDetailView(cipher: selectedCipher)
                    .id(selectedCipher.openVaultID)
            } else {
                ContentUnavailableView("选择验证码", systemImage: "clock")
            }
        default:
            if let selectedCipher {
                NavigationStack {
                    ItemDetailView(model: ItemDetailModel(cipher: selectedCipher), vault: vault) {
                        Task { await listModel.load() }
                    }
                }
                .id(selectedCipher.openVaultID)
            } else {
                ContentUnavailableView("选择一个条目", systemImage: "lock.shield")
            }
        }
    }

    private var syncStatusText: String {
        if syncModel.isSyncing { return "正在同步…" }
        if syncModel.errorMessage != nil { return "同步失败" }
        if let last = syncModel.lastSync {
            return "已同步 · \(last.formatted(.relative(presentation: .named)))"
        }
        return "尚未同步"
    }

    private func count(_ type: CipherType) -> Int {
        listModel.items.filter { CipherType(rawValue: $0.type) == type }.count
    }

    private func normalizeSelection() {
        guard !selectedSection.isTool else { selectedID = nil; return }
        if let selectedID, filteredItems.contains(where: { $0.openVaultID == selectedID }) {
            return
        }
        selectedID = filteredItems.first?.openVaultID
    }

    private func delete(_ cipher: PlaintextCipher) {
        guard let id = cipher.id else { return }
        Task {
            do {
                try await vault.deleteCipher(id: id)
                await listModel.load()
            } catch {
                operationError = "删除失败，条目未被更改。"
            }
        }
    }

    private var hasOperationError: Binding<Bool> {
        Binding(get: { operationError != nil }, set: { if !$0 { operationError = nil } })
    }
}
