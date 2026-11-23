import AppKit
import UIShared
import VaultRepository

@MainActor
enum MacSessionTimeoutChecks {
    static func run() async throws {
        try await localInactivityAndRealIdleAreIndependent()
        try await sleepAndWakeResolveRepositorySession()
        try await unconfirmedLockNeverLogsOut()
        try await launchActionsDoNotReuseAnUnlockKey()
        print("Session timeout: input deadline, system idle, sleep/wake, delayed signals, screen-lock verification and cold-launch actions passed.")
    }

    private static func localInactivityAndRealIdleAreIndependent() async throws {
        let fixture = Fixture(mode: .oneMinute)
        fixture.publish()
        fixture.observeUnlocked()
        fixture.systemIdle = 610
        fixture.advance(by: 40)
        fixture.application.post(name: NSApplication.didBecomeActiveNotification, object: nil)
        await fixture.monitor.awaitSystemActions()
        try require(fixture.actions.isEmpty, "numeric timeout ignores outside-App idle and resumed activation is not itself input")
        try require(fixture.monitor.acceptInput(), "local input resets an unexpired deadline")
        fixture.advance(by: 59)
        await fixture.monitor.enforceBeforeAccess()
        try require(fixture.actions.isEmpty, "numeric timeout has not crossed the new boundary")
        fixture.advance(by: 1)
        try require(!fixture.monitor.acceptInput(), "expired vault content does not receive the first returning input")
        await fixture.monitor.awaitSystemActions()
        try require(fixture.actions.map(\.action) == [.lock], "numeric expiry locks a focused or background vault exactly once")

        let idle = Fixture(mode: .onSystemIdle, action: .logOut)
        idle.publish()
        idle.observeUnlocked()
        idle.advance(by: 610)
        idle.systemIdle = 299
        await idle.monitor.enforceBeforeAccess()
        try require(idle.actions.isEmpty, "system-idle timeout ignores app inactivity and requires the system threshold")
        idle.systemIdle = 300
        idle.application.post(name: NSApplication.didBecomeActiveNotification, object: nil)
        await idle.monitor.awaitSystemActions()
        try require(idle.actions.map(\.action) == [.logOut], "system-idle timeout applies the selected action at five minutes")
    }

    private static func sleepAndWakeResolveRepositorySession() async throws {
        let fixture = Fixture(mode: .onSystemSleep, action: .logOut)
        fixture.publish()
        fixture.workspace.post(name: NSWorkspace.screensDidSleepNotification, object: nil)
        fixture.workspace.post(name: NSWorkspace.sessionDidResignActiveNotification, object: nil)
        await fixture.monitor.awaitSystemActions()
        try require(fixture.actions.isEmpty, "display sleep and user switch are not system sleep")

        let lookup = LookupGate()
        fixture.lookup = lookup
        fixture.workspace.post(name: NSWorkspace.willSleepNotification, object: nil)
        await lookup.waitForLookup()
        fixture.advance(by: 1)
        await lookup.resume()
        await fixture.monitor.awaitSystemActions()
        try require(fixture.actions.map(\.action) == [.logOut], "sleep expires an already-authenticated session without a cached unlocked UI lease")

        let nextLookup = LookupGate()
        fixture.lookup = nextLookup
        fixture.advance(by: 1)
        fixture.workspace.post(name: NSWorkspace.willSleepNotification, object: nil)
        await nextLookup.waitForLookup()
        fixture.advance(by: 1)
        fixture.publish()
        await nextLookup.resume()
        await fixture.monitor.awaitSystemActions()
        try require(fixture.actions.count == 1, "a delayed signal cannot expire a same-account replacement published after it")
        fixture.advance(by: 1)
        fixture.workspace.post(name: NSWorkspace.didWakeNotification, object: nil)
        await fixture.monitor.awaitSystemActions()
        try require(fixture.actions.count == 2, "wake catches a session published during the preceding sleep transition")

        let guardFixture = Fixture(mode: .oneMinute, action: .logOut)
        guardFixture.publish()
        guardFixture.workspace.post(name: NSWorkspace.sessionDidResignActiveNotification, object: nil)
        await guardFixture.monitor.awaitSystemActions()
        try require(guardFixture.actions.map(\.action) == [.lock], "supplemental safety lock does not log out on user switch")

        let returnFixture = Fixture(mode: .fiveMinutes)
        returnFixture.workspace.post(name: NSWorkspace.sessionDidResignActiveNotification, object: nil)
        returnFixture.advance(by: 1)
        returnFixture.publish()
        await returnFixture.monitor.awaitSystemActions()
        try require(!returnFixture.monitor.acceptInput(), "local input is not accepted while the user session is inactive")
        returnFixture.advance(by: 1)
        returnFixture.workspace.post(name: NSWorkspace.sessionDidBecomeActiveNotification, object: nil)
        await returnFixture.monitor.awaitSystemActions()
        try require(returnFixture.actions.map(\.action) == [.lock], "returning to the user locks a session published while switched away")
    }

    private static func unconfirmedLockNeverLogsOut() async throws {
        let fixture = Fixture(mode: .onSystemLock, action: .logOut)
        fixture.publish()
        fixture.observeUnlocked()
        fixture.distributed.post(name: Notification.Name("com.apple.screenIsLocked"), object: nil)
        await fixture.monitor.awaitSystemActions()
        try require(fixture.actions.map(\.action) == [.lock], "a distributed notification without confirmed state cannot log out")
        fixture.advance(by: 2)
        fixture.screenLocked = true
        fixture.application.post(name: NSApplication.didBecomeActiveNotification, object: nil)
        await fixture.monitor.awaitSystemActions()
        try require(fixture.actions.map(\.action) == [.lock, .logOut], "foreground access detects a confirmed screen lock before restoring content")
    }

    private static func launchActionsDoNotReuseAnUnlockKey() async throws {
        let fixture = Fixture(mode: .onRestart, action: .logOut)
        fixture.publish()
        await fixture.monitor.enforceColdLaunchIfNeeded()
        try require(fixture.actions.map(\.action) == [.logOut], "restart logout acts on the locked restored lease")
        fixture.settings.setMode(.never)
        fixture.publish()
        await fixture.monitor.enforceColdLaunchIfNeeded()
        try require(fixture.actions.count == 1 && fixture.settings.policy.action == .logOut,
                    "Never ignores the stored action without changing it for the other modes")
    }

    private static func require(_ condition: Bool, _ message: String) throws {
        if !condition { throw CheckFailure(message: "Session timeout: \(message)") }
    }
}

@MainActor
private final class Fixture {
    let settings = MacSessionTimeoutModel()
    let workspace = NotificationCenter()
    let application = NotificationCenter()
    let distributed = NotificationCenter()
    var lookup: LookupGate?
    var systemIdle: TimeInterval = 0
    var screenLocked = false
    private var now = ContinuousClock.now
    private var publishedAt: ContinuousClock.Instant?
    private var generation: UInt64 = 0
    private(set) var lease: AccountSessionLease?
    private(set) var actions: [(lease: AccountSessionLease, action: MacSessionTimeoutAction)] = []

    private(set) var monitor: MacSessionTimeoutMonitor!

    init(mode: MacSessionTimeoutMode, action: MacSessionTimeoutAction = .lock) {
        settings.selectAccount("fixture-account")
        settings.setMode(mode)
        settings.setAction(action)
        monitor = MacSessionTimeoutMonitor(settings: settings,
            now: { [unowned self] in now }, systemIdleSeconds: { [unowned self] in systemIdle },
            isScreenLocked: { [unowned self] in screenLocked }, sessionAt: { [unowned self] time, floor in
                if let lookup { self.lookup = nil; await lookup.pause() }
                guard let publishedAt, publishedAt <= time, floor.map({ publishedAt > $0 }) != false else { return nil }
                return lease
            }, apply: { [unowned self] expected, action, _ in
                guard lease == expected else { return .superseded }
                actions.append((expected, action))
                generation &+= 1
                if action == .logOut {
                    lease = nil
                    return .loggedOut
                }
                lease = AccountSessionLease(accountID: expected.accountID, generation: generation)
                return .locked
            })
        monitor.startListening(workspace: workspace, application: application, distributed: distributed, monitorsInput: false)
    }

    func advance(by seconds: Int) { now = now.advanced(by: .seconds(seconds)) }

    func publish() {
        generation &+= 1
        lease = AccountSessionLease(accountID: "fixture-account", generation: generation)
        publishedAt = now
    }

    func observeUnlocked() { monitor.observe(unlocked: lease, authenticated: lease) }
}

private actor LookupGate {
    private var reached: CheckedContinuation<Void, Never>?
    private var paused: CheckedContinuation<Void, Never>?

    func pause() async {
        await withCheckedContinuation { continuation in
            paused = continuation
            reached?.resume()
            reached = nil
        }
    }

    func waitForLookup() async {
        if paused != nil { return }
        await withCheckedContinuation { reached = $0 }
    }

    func resume() {
        paused?.resume()
        paused = nil
    }
}
