import AppKit
import Darwin
import OSLog

@main
struct MacRelaunchHelper {
    @MainActor
    static func main() async {
        guard CommandLine.arguments.count == 2,
              let parentPID = pid_t(CommandLine.arguments[1]), parentPID > 1,
              let app = enclosingApp() else { return }
        let currentParent = getppid()
        // The parent may have exited before this executable was scheduled.
        guard currentParent == parentPID || currentParent == 1,
              hasTerminationAuthorization(), waitForExit(of: parentPID) else { return }

        let configuration = NSWorkspace.OpenConfiguration()
        configuration.activates = false
        configuration.addsToRecentItems = false
        configuration.promptsUserIfNeeded = false
        configuration.allowsRunningApplicationSubstitution = false
        do {
            // Do not force a duplicate if the user already opened this installation again.
            _ = try await NSWorkspace.shared.openApplication(at: app, configuration: configuration)
        } catch {
            Logger(subsystem: "dev.moooyo.tessera", category: "LockedRelaunch")
                .error("Could not reopen the application after its locked relaunch.")
        }
    }

    private static func enclosingApp() -> URL? {
        guard let executable = Bundle.main.executableURL else { return nil }
        let helpers = executable.deletingLastPathComponent()
        let contents = helpers.deletingLastPathComponent()
        let app = contents.deletingLastPathComponent()
        guard helpers.lastPathComponent == "Helpers", contents.lastPathComponent == "Contents",
              app.pathExtension == "app" else { return nil }
        return app
    }

    private static func hasTerminationAuthorization() -> Bool {
        // Accept only a pipe, and do not leave a waiting helper behind indefinitely.
        var info = stat()
        guard fstat(STDIN_FILENO, &info) == 0, (info.st_mode & mode_t(S_IFMT)) == mode_t(S_IFIFO) else { return false }
        var input = pollfd(fd: STDIN_FILENO, events: Int16(POLLIN), revents: 0)
        guard poll(&input, 1, 30_000) == 1 else { return false }
        return (try? FileHandle.standardInput.read(upToCount: 1)) == Data([1])
    }

    private static func waitForExit(of pid: pid_t) -> Bool {
        if getppid() == 1 { return true }
        let queue = kqueue()
        guard queue >= 0 else { return false }
        defer { close(queue) }

        var registration = kevent(ident: UInt(pid), filter: Int16(EVFILT_PROC), flags: UInt16(EV_ADD | EV_ONESHOT),
                                  fflags: NOTE_EXIT, data: 0, udata: nil)
        if kevent(queue, &registration, 1, nil, 0, nil) == -1 {
            // The only safe registration failure is when the old process is already gone.
            return errno == ESRCH
        }
        var event = kevent()
        var timeout = timespec(tv_sec: 30, tv_nsec: 0)
        return kevent(queue, nil, 0, &event, 1, &timeout) == 1 && event.fflags & NOTE_EXIT != 0
    }
}
