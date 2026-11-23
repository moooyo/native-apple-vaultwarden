import AppKit
import AppShared

/// The only macOS pasteboard seam. Secret copies honor the user's clear-after policy and
/// only clear when the pasteboard still contains the value OpenVault placed there.
@MainActor
final class MacClipboard {
    private var ownedCopy: (pasteboard: NSPasteboard, change: Int)?
    private var pendingClear: Task<Void, Never>?
    private let wait: (Duration) async throws -> Void
    private let write: (String, NSPasteboard) -> Bool

    static let shared = MacClipboard()

    init(wait: @escaping (Duration) async throws -> Void = { try await Task.sleep(for: $0) },
         write: @escaping (String, NSPasteboard) -> Bool = { $1.setString($0, forType: .string) }) {
        self.wait = wait
        self.write = write
    }

    static func copy(_ value: String) {
        shared.copy(value, to: .general, expiresAfter: AppShared.Preference.clipboardLifetime(in: .standard))
    }

    @discardableResult
    static func copyItem(_ value: String) -> Bool {
        copyItem(value, from: NSApplication.shared.keyWindow)
    }

    @discardableResult
    static func copyItem(_ value: String, from window: NSWindow?) -> Bool {
        shared.copyItem(value, to: .general, preferences: .standard) {
            let application = NSApplication.shared
            guard let window, application.isActive, application.keyWindow === window, window.isVisible,
                  window.styleMask.contains(.miniaturizable), !window.isMiniaturized, window.attachedSheet == nil else { return }
            window.miniaturize(nil)
        }
    }

    @discardableResult
    func copyItem(_ value: String, to pasteboard: NSPasteboard, preferences: UserDefaults, minimize: () -> Void) -> Bool {
        guard copy(value, to: pasteboard, expiresAfter: AppShared.Preference.clipboardLifetime(in: preferences)) else { return false }
        if preferences.bool(forKey: MacClipboardPreference.minimizeAfterCopy) { minimize() }
        return true
    }

    @discardableResult
    func copy(_ value: String, to pasteboard: NSPasteboard, expiresAfter seconds: TimeInterval?) -> Bool {
        pendingClear?.cancel()
        pendingClear = nil
        ownedCopy = nil
        let change = pasteboard.clearContents()
        guard write(value, pasteboard), pasteboard.changeCount == change else { return false }
        guard let seconds else { return true }
        ownedCopy = (pasteboard, change)
        pendingClear = Task { @MainActor [weak self, wait] in
            do { try await wait(.seconds(seconds)) } catch { return }
            guard !Task.isCancelled else { return }
            self?.clearOwnedCopy()
        }
        return true
    }

    func clearOwnedCopy() {
        pendingClear?.cancel()
        pendingClear = nil
        let copy = ownedCopy
        ownedCopy = nil
        guard let copy, copy.pasteboard.changeCount == copy.change else { return }
        copy.pasteboard.clearContents()
    }
}
