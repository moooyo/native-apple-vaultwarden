import AppKit
import DesignSystem

/// The only macOS pasteboard seam. Secret copies honor the user's clear-after policy and
/// only clear when the pasteboard still contains the value OpenVault placed there.
@MainActor
enum MacClipboard {
    private static var pendingClear: Task<Void, Never>?

    static func copy(_ value: String) {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(value, forType: .string)

        pendingClear?.cancel()
        let seconds = configuredTimeout
        guard seconds > 0 else { return }
        pendingClear = Task { @MainActor in
            try? await Task.sleep(for: .seconds(seconds))
            guard !Task.isCancelled else { return }
            clearIfStill(value)
        }
    }

    static func clearIfStill(_ value: String) {
        let pasteboard = NSPasteboard.general
        if pasteboard.string(forType: .string) == value {
            pasteboard.clearContents()
        }
    }

    private static var configuredTimeout: Double {
        let defaults = UserDefaults.standard
        guard defaults.object(forKey: OpenVaultPreferenceKey.clipboardTimeout) != nil else { return 60 }
        return max(0, defaults.double(forKey: OpenVaultPreferenceKey.clipboardTimeout))
    }
}
