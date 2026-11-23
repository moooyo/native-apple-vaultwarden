import SwiftUI

struct MacWorkspaceActions {
    let newItemTitle: String
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
            Button(actions?.newItemTitle ?? MacLocalization.text("New item…")) { actions?.newItem() }
                .keyboardShortcut("n").disabled(actions == nil)
            Button(MacLocalization.text("New folder…")) { actions?.newFolder() }
                .keyboardShortcut("n", modifiers: [.command, .shift]).disabled(actions == nil)
            Button(MacLocalization.text("New Send…")) { actions?.newSend() }
                .keyboardShortcut("n", modifiers: [.command, .option]).disabled(actions == nil)
            Divider()
            Button(MacLocalization.text("Import…")) { actions?.showImport() }
                .keyboardShortcut("i", modifiers: [.command, .shift]).disabled(actions == nil)
            Button(MacLocalization.text("Export…")) { actions?.showExport() }
                .keyboardShortcut("e", modifiers: [.command, .shift]).disabled(actions == nil)
        }
        CommandGroup(after: .textEditing) {
            Button(MacLocalization.text("Search vault")) { actions?.search() }
                .keyboardShortcut("k").disabled(actions == nil)
        }
        CommandGroup(after: .sidebar) {
            Button(MacLocalization.text(history == true ? "Hide generator history" : "Show generator history")) { history?.toggle() }
                .keyboardShortcut("h", modifiers: [.command, .option, .shift]).disabled(history == nil || actions == nil)
        }
        CommandMenu(MacLocalization.text("Vault")) {
            Button(MacLocalization.text("Sync now")) { actions?.sync?() }
                .keyboardShortcut("r").disabled(actions?.sync == nil)
            Button(MacLocalization.text("Archive item")) { actions?.archive?() }
                .keyboardShortcut("a", modifiers: [.command, .shift]).disabled(actions?.archive == nil)
            Button(MacLocalization.text(send == nil ? "Move to Trash" : "Delete Send…")) {
                if let send { send.delete() } else { actions?.trash?() }
            }
            .keyboardShortcut(.delete, modifiers: .command).disabled(actions == nil || (actions?.trash == nil && send == nil))
            Divider()
            Button(MacLocalization.text("Lock vault")) { actions?.lock() }
                .keyboardShortcut("l", modifiers: [.command, .shift]).disabled(actions == nil)
        }
    }
}
