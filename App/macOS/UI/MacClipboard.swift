import AppKit
import AppShared

/// The only macOS pasteboard seam. Secret copies honor the user's clear-after policy and
/// only clear when the pasteboard still contains the value OpenVault placed there.
@MainActor
final class MacClipboard {
    private var ownedCopy: (pasteboard: NSPasteboard, change: Int)?
    private var pendingClear: Task<Void, Never>?
    private let wait: (Duration) async throws -> Void

    static let shared = MacClipboard()

    init(wait: @escaping (Duration) async throws -> Void = { try await Task.sleep(for: $0) }) {
        self.wait = wait
    }

    static func copy(_ value: String) {
        shared.copy(value, to: .general, expiresAfter: AppShared.Preference.clipboardLifetime(in: .standard))
    }

    func copy(_ value: String, to pasteboard: NSPasteboard, expiresAfter seconds: TimeInterval?) {
        pendingClear?.cancel()
        pendingClear = nil
        ownedCopy = nil
        let change = pasteboard.clearContents()
        guard pasteboard.setString(value, forType: .string), let seconds, pasteboard.changeCount == change else { return }
        ownedCopy = (pasteboard, change)
        pendingClear = Task { @MainActor [weak self, wait] in
            do { try await wait(.seconds(seconds)) } catch { return }
            guard !Task.isCancelled else { return }
            self?.clearOwnedCopy()
        }
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

@MainActor
final class MacClipboardTerminationDelegate: NSObject, NSApplicationDelegate {
    func applicationWillTerminate(_ notification: Notification) { MacClipboard.shared.clearOwnedCopy() }
}
