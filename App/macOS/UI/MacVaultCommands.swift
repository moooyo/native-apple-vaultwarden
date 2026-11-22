import SwiftUI

struct MacWorkspaceActions {
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

extension FocusedValues {
    @Entry var macWorkspaceActions: MacWorkspaceActions?
}

struct MacVaultCommands: Commands {
    @FocusedValue(\.macWorkspaceActions) private var actions

    var body: some Commands {
        CommandGroup(replacing: .newItem) {
            Button("新建条目…") { actions?.newItem() }
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
        CommandMenu("保险库") {
            Button("立即同步") { actions?.sync?() }
                .keyboardShortcut("r").disabled(actions?.sync == nil)
            Button("归档条目") { actions?.archive?() }
                .keyboardShortcut("a", modifiers: [.command, .shift]).disabled(actions?.archive == nil)
            Button("移到回收站") { actions?.trash?() }
                .keyboardShortcut(.delete, modifiers: .command).disabled(actions?.trash == nil)
            Divider()
            Button("锁定保险库") { actions?.lock() }
                .keyboardShortcut("l", modifiers: [.command, .shift]).disabled(actions == nil)
        }
    }
}
