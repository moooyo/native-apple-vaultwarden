@MainActor
enum MacLockedRelaunchChecks {
    static func run() async throws {
        try await validatesAfterDelay(current: true)
        try await validatesAfterDelay(current: false)
        try await cancelsWhileWaiting()
        try await cancelsDuringValidation()
        try await newerLockSupersedesPendingRelaunch()
        print("Locked relaunch: fixed delay, session validation, credential cancellation and replacement passed.")
    }

    private static func validatesAfterDelay(current: Bool) async throws {
        let sleep = Gate()
        var delays: [Duration] = []
        var validations = 0
        var restarts = 0
        let relaunch = MacLockedRelaunch(sleep: { delay in
            delays.append(delay)
            await sleep.pause()
        }, restart: { restarts += 1 })
        let task = relaunch.schedule {
            validations += 1
            return current
        }
        await sleep.waitUntilPaused()
        try require(delays == [.seconds(120)] && validations == 0 && restarts == 0,
                    "the current session must not be checked or restarted before the delay")
        sleep.resume()
        await task.value
        try require(validations == 1 && restarts == (current ? 1 : 0),
                    "only a still-current locked session can restart")
    }

    private static func cancelsWhileWaiting() async throws {
        let sleep = Gate()
        var validations = 0
        var restarts = 0
        let relaunch = MacLockedRelaunch(sleep: { _ in await sleep.pause() }, restart: { restarts += 1 })
        let generation = relaunch.activityGeneration
        let task = relaunch.schedule { validations += 1; return true }
        await sleep.waitUntilPaused()
        relaunch.cancel()
        sleep.resume()
        await task.value
        try require(relaunch.activityGeneration != generation && validations == 0 && restarts == 0,
                    "activity both invalidates an in-flight lock and clears any existing timer")
    }

    private static func cancelsDuringValidation() async throws {
        let validation = Gate()
        var restarts = 0
        let relaunch = MacLockedRelaunch(sleep: { _ in }, restart: { restarts += 1 })
        let task = relaunch.schedule { await validation.pause(); return true }
        await validation.waitUntilPaused()
        relaunch.cancel()
        validation.resume()
        await task.value
        try require(restarts == 0, "cancellation while awaiting validation prevents the restart")
    }

    private static func newerLockSupersedesPendingRelaunch() async throws {
        let validation = Gate()
        var restarts = 0
        let relaunch = MacLockedRelaunch(sleep: { _ in }, restart: { restarts += 1 })
        let old = relaunch.schedule { await validation.pause(); return true }
        await validation.waitUntilPaused()
        let new = relaunch.schedule { true }
        await new.value
        validation.resume()
        await old.value
        try require(restarts == 1, "the previous lock cannot restart after a replacement lock")
    }

    private static func require(_ condition: Bool, _ message: String) throws {
        if !condition { throw CheckFailure(message: "Locked relaunch: \(message)") }
    }

    @MainActor
    private final class Gate {
        private var paused: CheckedContinuation<Void, Never>?
        private var waiting: CheckedContinuation<Void, Never>?

        func pause() async {
            await withCheckedContinuation { continuation in
                paused = continuation
                waiting?.resume()
                waiting = nil
            }
        }

        func waitUntilPaused() async {
            if paused != nil { return }
            await withCheckedContinuation { waiting = $0 }
        }

        func resume() {
            paused?.resume()
            paused = nil
        }
    }
}
