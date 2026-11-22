import AppKit
import AppShared

@MainActor
enum ClipboardFunctionalChecks {
    static func run() async throws {
        let board = NSPasteboard.withUniqueName()
        defer { board.releaseGlobally() }
        let suite = "openvault.review.clipboard.\(UUID().uuidString)"
        guard let preferences = UserDefaults(suiteName: suite) else { throw Failure("Could not create isolated preferences") }
        defer { preferences.removePersistentDomain(forName: suite) }
        preferences.set(30, forKey: AppShared.Preference.clipboardTimeout)
        let lifetime = AppShared.Preference.clipboardLifetime(in: preferences)
        let delays = Delays()
        let clipboard = MacClipboard(wait: delays.wait)
        defer { clipboard.clearOwnedCopy(); delays.releaseAll() }

        clipboard.copy("First review value", to: board, expiresAfter: lifetime)
        try await delays.awaitCount(1)
        try require(board.string(forType: .string) == "First review value" && delays.durations == [.seconds(30)], "Copy schedules the configured timeout")
        delays.release(0)
        try await waitFor("The timeout clears the owned copy") { board.string(forType: .string) == nil }

        clipboard.copy("Earlier review value", to: board, expiresAfter: lifetime)
        try await delays.awaitCount(2)
        clipboard.copy("Replacement review value", to: board, expiresAfter: lifetime)
        try await delays.awaitCount(3)
        let replacement = board.changeCount
        delays.release(1)
        try await delays.awaitReturned(2)
        try require(board.changeCount == replacement && board.string(forType: .string) == "Replacement review value", "The cancelled older timer cannot clear a newer copy")
        delays.release(2)
        try await waitFor("The replacement has its own expiry") { board.string(forType: .string) == nil }

        clipboard.copy("Same review value", to: board, expiresAfter: lifetime)
        try await delays.awaitCount(4)
        board.clearContents()
        try require(board.setString("Same review value", forType: .string), "Write a separate owner's equal text")
        let otherChange = board.changeCount
        delays.release(3)
        try await delays.awaitReturned(4)
        try require(board.changeCount == otherChange && board.string(forType: .string) == "Same review value", "An equal string from a later owner survives expiry")

        clipboard.copy("Short lived review value", to: board, expiresAfter: lifetime)
        try await delays.awaitCount(5)
        preferences.set(0, forKey: AppShared.Preference.clipboardTimeout)
        let never = AppShared.Preference.clipboardLifetime(in: preferences)
        try require(never == nil, "The explicit never preference has no timeout")
        clipboard.copy("Indefinite review value", to: board, expiresAfter: never)
        let indefinite = board.changeCount
        delays.release(4)
        try await delays.awaitReturned(5)
        clipboard.clearOwnedCopy()
        try require(board.changeCount == indefinite && board.string(forType: .string) == "Indefinite review value" && delays.durations.count == 5,
                    "A prior timeout and normal cleanup must both preserve a never-expiring copy")

        let shared = MacClipboard.shared
        let termination = MacClipboardTerminationDelegate()
        let closing = Notification(name: NSApplication.willTerminateNotification, object: NSApplication.shared)
        shared.copy("Quit review value", to: board, expiresAfter: lifetime)
        termination.applicationWillTerminate(closing)
        try require(board.string(forType: .string) == nil, "The real termination delegate clears the pending copy synchronously")
        shared.copy("Quit replacement review", to: board, expiresAfter: lifetime)
        board.clearContents()
        try require(board.setString("Other review owner", forType: .string), "Replace the quitting owner's copy")
        let lastOwner = board.changeCount
        termination.applicationWillTerminate(closing)
        termination.applicationWillTerminate(closing)
        try require(board.changeCount == lastOwner && board.string(forType: .string) == "Other review owner", "Repeated termination never clears a later owner's content")
        print("Named pasteboard: timeout, replacement, foreign ownership, never and synchronous normal termination passed.")
    }

    private static func require(_ result: Bool, _ message: String) throws {
        if !result { throw Failure(message) }
    }

    private static func waitFor(_ message: String, _ condition: () -> Bool) async throws {
        let end = ContinuousClock.now.advanced(by: .seconds(3))
        while !condition() {
            guard ContinuousClock.now < end else { throw Failure(message) }
            try await Task.sleep(for: .milliseconds(8))
        }
    }

    @MainActor private final class Delays {
        var durations: [Duration] = []
        var returned = 0
        var pending: [Int: CheckedContinuation<Void, Never>] = [:]

        func wait(_ duration: Duration) async throws {
            let index = durations.count
            durations.append(duration)
            await withCheckedContinuation { pending[index] = $0 }
            returned += 1
        }

        func awaitCount(_ expected: Int) async throws {
            try await waitFor("The expected expiry was not scheduled") { self.durations.count == expected }
        }
        func awaitReturned(_ expected: Int) async throws {
            try await waitFor("An expiry did not complete") { self.returned == expected }
        }
        func release(_ index: Int) { pending.removeValue(forKey: index)?.resume() }
        func releaseAll() { for index in Array(pending.keys) { release(index) } }
    }

    private struct Failure: Error, CustomStringConvertible {
        let description: String
        init(_ message: String) { description = "Clipboard check failed: \(message)" }
    }
}
