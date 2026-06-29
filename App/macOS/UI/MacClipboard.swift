// Xcode-only target (UI-iOS / UI-mac). Not part of the SPM build.
//
// MacClipboard — the macOS pasteboard seam. UIShared view models RETURN the string to
// copy (never touching the pasteboard), so the platform copy lives here in a macOS-only
// file using `NSPasteboard`.

import AppKit

enum MacClipboard {
    /// Copy `value` to the general pasteboard. macOS has no per-item expiration like iOS,
    /// so a clear-after policy (if desired) is handled by the app via a timed clear.
    static func copy(_ value: String) {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(value, forType: .string)
    }

    /// Clear the pasteboard if it still holds `value` (used for a delayed auto-clear of a
    /// copied secret). No-op if the user has copied something else since.
    static func clearIfStill(_ value: String) {
        let pasteboard = NSPasteboard.general
        if pasteboard.string(forType: .string) == value {
            pasteboard.clearContents()
        }
    }
}
