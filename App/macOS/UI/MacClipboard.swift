import AppKit
import AppShared

/// The only macOS pasteboard seam. Secret copies honor the user's clear-after policy and
/// only clear when the pasteboard still contains the value OpenVault placed there.
@MainActor
enum MacClipboard {
    private static var pendingClear: Task<Void, Never>?

    static func copy(_ value: String) {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pendingClear?.cancel()
        guard pasteboard.setString(value, forType: .string),
              let seconds = AppShared.Preference.clipboardLifetime(in: .standard) else { return }
        let change = pasteboard.changeCount
        pendingClear = Task { @MainActor in
            try? await Task.sleep(for: .seconds(seconds))
            guard !Task.isCancelled, pasteboard.changeCount == change else { return }
            pasteboard.clearContents()
        }
    }
}
