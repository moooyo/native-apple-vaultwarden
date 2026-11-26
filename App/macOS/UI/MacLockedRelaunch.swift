import AppKit
import OSLog

@MainActor
final class MacLockedRelaunch {
    static let shared = MacLockedRelaunch(restart: MacAppProcessRelaunch.request)

    private static let delay: Duration = .seconds(120)
    private let sleep: @MainActor (Duration) async throws -> Void
    private let restart: @MainActor () -> Void
    private var pending: Task<Void, Never>?

    /// Also invalidates a lock operation that is still awaiting completion before it can schedule.
    private(set) var activityGeneration: UInt64 = 0

    init(sleep: @escaping @MainActor (Duration) async throws -> Void = { try await Task.sleep(for: $0) },
         restart: @escaping @MainActor () -> Void) {
        self.sleep = sleep
        self.restart = restart
    }

    /// Schedule only after an unlocked session has actually locked, not when routing to a restored lock screen.
    @discardableResult
    func schedule(ifStillLocked: @escaping @MainActor () async -> Bool) -> Task<Void, Never> {
        pending?.cancel()
        let task = Task { [weak self, sleep] in
            defer { if !Task.isCancelled { self?.pending = nil } }
            do { try await sleep(Self.delay) } catch { return }
            guard !Task.isCancelled, self != nil else { return }
            let valid = await ifStillLocked()
            // Credential activity or a replacement lock may have arrived during validation.
            guard valid, !Task.isCancelled else { return }
            self?.restart()
        }
        pending = task
        return task
    }

    func cancel() {
        activityGeneration &+= 1
        pending?.cancel()
        pending = nil
    }

    deinit { pending?.cancel() }
}

@MainActor
private enum MacAppProcessRelaunch {
    private static let logger = Logger(subsystem: "dev.moooyo.tessera", category: "LockedRelaunch")

    static func request() {
        #if !OPENVAULT_MAC_FIXTURE
        guard let application = NSApp else { return }
        let helper = Process()
        helper.executableURL = Bundle.main.bundleURL
            .appending(path: "Contents/Helpers/OpenVaultRelaunchHelper", directoryHint: .notDirectory)
        helper.arguments = [String(ProcessInfo.processInfo.processIdentifier)]
        let input = Pipe()
        let writer = input.fileHandleForWriting
        // A failed helper must not send SIGPIPE to the application during normal AppKit shutdown.
        guard fcntl(writer.fileDescriptor, F_SETNOSIGPIPE, 1) != -1 else { return }
        helper.standardInput = input
        do { try helper.run() } catch {
            logger.error("Could not start the locked relaunch helper; staying open.")
            return
        }

        // Authorize reopening only if this request reaches AppKit's normal termination path.
        // The helper separately waits for the old process to exit and release its resources.
        let center = NotificationCenter.default
        let observer = center.addObserver(forName: NSApplication.willTerminateNotification, object: application,
                                          queue: nil) { _ in
            try? writer.write(contentsOf: Data([1]))
        }
        defer {
            center.removeObserver(observer)
            try? writer.close()
        }
        application.terminate(nil)
        #endif
    }
}
