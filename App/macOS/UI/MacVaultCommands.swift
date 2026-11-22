import SwiftUI

struct MacWorkspaceActions {
    let newItemTitle: LocalizedStringKey
    let newItem: () -> Void
    let newFolder: () -> Void
    let newSend: () -> Void
    let showImport: () -> Void
    let showExport: () -> Void
    let search: () -> Void
    let sync: (() -> Void)?
    let archive: (() -> Void)?
    let trash: (() -> Void)?
    let lock: () -> Void
}

struct MacSendCommandActions {
    let edit: () -> Void
    let delete: () -> Void
}

extension FocusedValues {
    @Entry var macWorkspaceActions: MacWorkspaceActions?
    @Entry var macSendActions: MacSendCommandActions?
    @Entry var macHistoryVisible: Binding<Bool>?
}

struct MacVaultCommands: Commands {
    @FocusedValue(\.macWorkspaceActions) private var actions
    @FocusedValue(\.macSendActions) private var send
    @FocusedBinding(\.macHistoryVisible) private var history: Bool?

    var body: some Commands {
        CommandGroup(replacing: .newItem) {
            Button(actions?.newItemTitle ?? "新建条目…") { actions?.newItem() }
                .keyboardShortcut("n").disabled(actions == nil)
            Button("新建文件夹…") { actions?.newFolder() }
                .keyboardShortcut("n", modifiers: [.command, .shift]).disabled(actions == nil)
            Button("新建 Send…") { actions?.newSend() }
                .keyboardShortcut("n", modifiers: [.command, .option]).disabled(actions == nil)
            Divider()
            Button("导入…") { actions?.showImport() }
                .keyboardShortcut("i", modifiers: [.command, .shift]).disabled(actions == nil)
            Button("导出…") { actions?.showExport() }
                .keyboardShortcut("e", modifiers: [.command, .shift]).disabled(actions == nil)
        }
        CommandGroup(after: .textEditing) {
            Button("搜索保险库") { actions?.search() }
                .keyboardShortcut("k").disabled(actions == nil)
        }
        CommandGroup(after: .sidebar) {
            Button(history == true ? "隐藏生成历史" : "显示生成历史") { history?.toggle() }
                .keyboardShortcut("h", modifiers: [.command, .option, .shift]).disabled(history == nil || actions == nil)
        }
        CommandMenu("保险库") {
            Button("立即同步") { actions?.sync?() }
                .keyboardShortcut("r").disabled(actions?.sync == nil)
            Button("归档条目") { actions?.archive?() }
                .keyboardShortcut("a", modifiers: [.command, .shift]).disabled(actions?.archive == nil)
            Button(send == nil ? "移到回收站" : "删除 Send…") {
                if let send { send.delete() } else { actions?.trash?() }
            }
            .keyboardShortcut(.delete, modifiers: .command).disabled(actions == nil || (actions?.trash == nil && send == nil))
            Divider()
            Button("锁定保险库") { actions?.lock() }
                .keyboardShortcut("l", modifiers: [.command, .shift]).disabled(actions == nil)
        }
    }
}
