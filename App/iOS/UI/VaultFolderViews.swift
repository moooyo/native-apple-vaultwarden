import SwiftUI
import UIShared
import VaultRepository
import DesignSystem

enum VaultFolderEditor {
    case create
    case rename(PlaintextFolder)
    case delete(PlaintextFolder)
}

@available(iOS 27.0, *)
extension View {
    func vaultFolderDialogs(editor: Binding<VaultFolderEditor?>, model: VaultListModel,
                            vault: VaultService, onDeleted: @escaping (String) -> Void = { _ in }) -> some View {
        modifier(VaultFolderDialogs(editor: editor, model: model, vault: vault, onDeleted: onDeleted))
    }
}

@available(iOS 27.0, *)
private struct VaultFolderDialogs: ViewModifier {
    @Binding var editor: VaultFolderEditor?
    let model: VaultListModel
    let vault: VaultService
    let onDeleted: (String) -> Void
    @State private var draft = ""
    @State private var failed = false

    private var editingName: Binding<Bool> {
        Binding(get: {
            switch editor {
            case .create, .rename: true
            default: false
            }
        }, set: { if !$0 { editor = nil } })
    }

    private var deleting: PlaintextFolder? {
        if case let .delete(folder) = editor { return folder }
        return nil
    }

    private var initialName: String? {
        switch editor {
        case .create: ""
        case let .rename(folder): folder.name
        default: nil
        }
    }

    func body(content: Content) -> some View {
        content
            .onChange(of: initialName) { _, value in
                if let value { draft = value }
            }
            .alert(initialName == "" ? "新建文件夹" : "重命名文件夹", isPresented: editingName, presenting: editor) { operation in
                TextField("文件夹名称", text: $draft)
                Button("取消", role: .cancel) {}
                Button("存储") { save(operation, name: draft.trimmingCharacters(in: .whitespacesAndNewlines)) }
                    .disabled(draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
            .alert("删除文件夹？", isPresented: Binding(get: { deleting != nil },
                                                    set: { if !$0 { editor = nil } }), presenting: deleting) { folder in
                Button("取消", role: .cancel) {}
                Button("删除文件夹", role: .destructive) { remove(folder) }
            } message: { folder in
                let count = [model.items, model.archivedItems, model.trashedItems]
                    .reduce(0) { $0 + $1.count(where: { $0.folderID == folder.id }) }
                Text("“\(folder.name)”中的 \(count) 个条目将移到“无文件夹”。条目不会被删除。")
            }
            .alert("文件夹操作未完成", isPresented: $failed) {
                Button("好", role: .cancel) {}
            } message: { Text("请刷新保险库后重试。") }
    }

    private func save(_ operation: VaultFolderEditor, name: String) {
        guard !name.isEmpty else { return }
        Task {
            do {
                switch operation {
                case .create: _ = try await vault.createFolder(name: name)
                case let .rename(folder): try await vault.renameFolder(id: folder.id, name: name)
                case .delete: return
                }
                await model.load()
            } catch { failed = true }
        }
    }

    private func remove(_ folder: PlaintextFolder) {
        Task {
            do {
                try await vault.deleteFolder(id: folder.id)
                await model.load()
                onDeleted(folder.id)
            } catch { failed = true }
        }
    }
}

@available(iOS 27.0, *)
struct VaultFolderLink: View {
    let id: String?
    let model: VaultListModel
    let vault: VaultService

    var body: some View {
        NavigationLink {
            VaultFolderView(id: id, model: model, vault: vault)
        } label: {
            HStack {
                Label(model.folders.first { $0.id == id }?.name ?? "无文件夹",
                      systemImage: id == nil ? "tray" : "folder")
                Spacer()
                Text(model.items.count(where: { $0.folderID == id }), format: .number)
                    .foregroundStyle(.secondary).monospacedDigit()
            }
        }
        .accessibilityIdentifier("vault.folder.\(id ?? "unfiled")")
    }
}

@available(iOS 27.0, *)
struct VaultFoldersView: View {
    let model: VaultListModel
    let vault: VaultService
    @State private var editor: VaultFolderEditor?

    var body: some View {
        List {
            if let message = model.errorMessage { VaultListError(message: message) }
            ForEach(model.folders) { folder in
                VaultFolderLink(id: folder.id, model: model, vault: vault)
                    .swipeActions(edge: .trailing, allowsFullSwipe: false) { actions(for: folder) }
                    .contextMenu { actions(for: folder) }
            }
        }
        .listStyle(.insetGrouped)
        .environment(\.defaultMinListRowHeight, 52)
        .navigationTitle("文件夹")
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button("新建文件夹", systemImage: "plus") { editor = .create }
            }
        }
        .overlay {
            if model.folders.isEmpty, model.errorMessage == nil {
                if model.isLoading { ProgressView() }
                else { ContentUnavailableView("没有文件夹", systemImage: "folder") }
            }
        }
        .vaultFolderDialogs(editor: $editor, model: model, vault: vault)
        .task { await model.load() }
    }

    @ViewBuilder private func actions(for folder: PlaintextFolder) -> some View {
        Button(role: .destructive) { editor = .delete(folder) } label: {
            Label("删除文件夹", systemImage: "trash")
        }
        Button { editor = .rename(folder) } label: { Label("重命名", systemImage: "pencil") }
    }
}

@available(iOS 27.0, *)
struct VaultFolderView: View {
    let id: String?
    let model: VaultListModel
    let vault: VaultService
    @Environment(\.dismiss) private var dismiss
    @State private var editor: VaultFolderEditor?
    @State private var adding = false

    private var folder: PlaintextFolder? { model.folders.first { $0.id == id } }

    var body: some View {
        let items = VaultSortOrder.name.sorted(model.items.filter { $0.folderID == id })
        List {
            if let message = model.errorMessage { VaultListError(message: message) }
            if items.isEmpty {
                ContentUnavailableView("此文件夹为空", systemImage: "folder")
            } else {
                VaultItemLinks(items: items, model: model, vault: vault)
            }
        }
        .listStyle(.insetGrouped)
        .navigationTitle(folder?.name ?? (id == nil ? "无文件夹" : "文件夹"))
        .toolbar {
            ToolbarItemGroup(placement: .topBarTrailing) {
                if let folder {
                    Menu {
                        Button("重命名", systemImage: "pencil") { editor = .rename(folder) }
                        Button("删除文件夹", systemImage: "trash", role: .destructive) { editor = .delete(folder) }
                    } label: { Label("文件夹操作", systemImage: "ellipsis") }
                }
                Button("在此文件夹新建条目", systemImage: "plus") { adding = true }
                    .disabled(id != nil && folder == nil)
            }
        }
        .sheet(isPresented: $adding) {
            NavigationStack {
                ItemEditView(vault: vault, initialFolderID: id) { _ in
                    adding = false
                    Task { await model.load() }
                }
            }
            .presentationDetents([.large])
        }
        .refreshable { await model.refresh() }
        .vaultFolderDialogs(editor: $editor, model: model, vault: vault) { _ in dismiss() }
    }
}
