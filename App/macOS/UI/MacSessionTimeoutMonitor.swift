import AppKit
import CoreGraphics
import UIShared
import VaultRepository

@MainActor
final class MacSessionTimeoutMonitor: NSObject {
    enum Signal: Sendable {
        case sleep, wake, userSwitch, returnToUser, activate, lockHint, unlockHint
    }

    private struct SystemEvent {
        let trigger: MacSessionTimeoutTrigger
        let occurredAt: ContinuousClock.Instant
        let publishedAfter: ContinuousClock.Instant?
    }

    private static let screenLocked = Notification.Name("com.apple.screenIsLocked")
    private static let screenUnlocked = Notification.Name("com.apple.screenIsUnlocked")
    private static let anyInput = CGEventType(rawValue: UInt32.max)!

    private let settings: MacSessionTimeoutModel
    private let sessionAt: @MainActor (ContinuousClock.Instant, ContinuousClock.Instant?) async -> AccountSessionLease?
    private let apply: @MainActor (AccountSessionLease, MacSessionTimeoutAction, ContinuousClock.Instant?) async -> SessionTimeoutResult
    private let now: @MainActor () -> ContinuousClock.Instant
    private let systemIdleSeconds: @MainActor () -> TimeInterval
    private let isScreenLocked: @MainActor () -> Bool
    private var inactivity = MacSessionInactivity()
    private var authenticatedLease: AccountSessionLease?
    private var timer: Task<Void, Never>?
    private var lockHintTask: Task<Void, Never>?
    private var pending: Task<Void, Never>?
    private var systemEventTask: Task<Void, Never>?
    private var systemEvents: [SystemEvent] = []
    private var lastSleep: ContinuousClock.Instant?
    private var lastUserSwitch: ContinuousClock.Instant?
    private var lastLockHint: ContinuousClock.Instant?
    private var hasDispatchedSystemIdle = false
    private var hasDispatchedConfirmedLock = false
    private var observers: [(NotificationCenter, NSObjectProtocol)] = []
    private var systemDistributedObserver: DistributedNotificationCenter?
    private var localInputMonitor: Any?

    init(settings: MacSessionTimeoutModel,
         now: @escaping @MainActor () -> ContinuousClock.Instant = { .now },
         systemIdleSeconds: @escaping @MainActor () -> TimeInterval = MacSessionTimeoutMonitor.readSystemIdleSeconds,
         isScreenLocked: @escaping @MainActor () -> Bool = MacSessionTimeoutMonitor.isSessionScreenLocked,
         sessionAt: @escaping @MainActor (ContinuousClock.Instant, ContinuousClock.Instant?) async -> AccountSessionLease?,
         apply: @escaping @MainActor (AccountSessionLease, MacSessionTimeoutAction, ContinuousClock.Instant?) async -> SessionTimeoutResult) {
        self.settings = settings
        self.now = now
        self.systemIdleSeconds = systemIdleSeconds
        self.isScreenLocked = isScreenLocked
        self.sessionAt = sessionAt
        self.apply = apply
        super.init()
        settings.onPolicyChanged = { [weak self] in self?.policyChanged() }
    }

    func startListening(workspace: NotificationCenter = NSWorkspace.shared.notificationCenter,
                        application: NotificationCenter = .default,
                        distributed: NotificationCenter = DistributedNotificationCenter.default(),
                        monitorsInput: Bool = true) {
        guard observers.isEmpty else { return }
        addObserver(workspace, NSWorkspace.willSleepNotification, signal: .sleep)
        addObserver(workspace, NSWorkspace.didWakeNotification, signal: .wake)
        addObserver(workspace, NSWorkspace.sessionDidResignActiveNotification, signal: .userSwitch)
        addObserver(workspace, NSWorkspace.sessionDidBecomeActiveNotification, signal: .returnToUser)
        addObserver(application, NSApplication.didBecomeActiveNotification, signal: .activate)
        addObserver(application, .NSApplicationProtectedDataWillBecomeUnavailable, signal: .lockHint, object: NSApp)
        if let system = distributed as? DistributedNotificationCenter {
            system.addObserver(self, selector: #selector(receiveDistributedSignal(_:)), name: Self.screenLocked,
                               object: nil, suspensionBehavior: .deliverImmediately)
            system.addObserver(self, selector: #selector(receiveDistributedSignal(_:)), name: Self.screenUnlocked,
                               object: nil, suspensionBehavior: .deliverImmediately)
            systemDistributedObserver = system
        } else {
            addObserver(distributed, Self.screenLocked, signal: .lockHint)
            addObserver(distributed, Self.screenUnlocked, signal: .unlockHint)
        }

        guard monitorsInput else { return }
        let inputEvents: NSEvent.EventTypeMask = [.leftMouseDown, .rightMouseDown, .otherMouseDown, .keyDown, .scrollWheel]
        localInputMonitor = NSEvent.addLocalMonitorForEvents(matching: inputEvents) { [weak self] event in
            self?.acceptInput() == false ? nil : event
        }
    }

    isolated deinit {
        if let localInputMonitor { NSEvent.removeMonitor(localInputMonitor) }
        for (center, token) in observers { center.removeObserver(token) }
        systemDistributedObserver?.removeObserver(self)
        timer?.cancel()
        lockHintTask?.cancel()
        systemEventTask?.cancel()
    }

    func observe(unlocked: AccountSessionLease?, authenticated: AccountSessionLease?) {
        let changed = authenticated != authenticatedLease
        let changedAccount = authenticated?.accountID != authenticatedLease?.accountID
        authenticatedLease = authenticated
        let changedInactivity = inactivity.observe(unlocked, at: now())
        if changedAccount {
            hasDispatchedSystemIdle = false
            hasDispatchedConfirmedLock = false
        }
        if changed || changedInactivity { evaluateAndSchedule() }
    }

    func enforceBeforeAccess() async {
        evaluateAndSchedule()
        await awaitSystemActions()
    }

    func awaitSystemActions() async {
        while let task = lockHintTask ?? systemEventTask ?? pending { await task.value }
    }

    func enforceColdLaunchIfNeeded() async {
        enqueue(.coldLaunch, at: now())
        await awaitSystemActions()
    }

    private func waitForPending() async {
        while let pending { await pending.value }
    }

    private func addObserver(_ center: NotificationCenter, _ name: Notification.Name, signal: Signal, object: AnyObject? = nil) {
        let token = center.addObserver(forName: name, object: object, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.receive(signal) }
        }
        observers.append((center, token))
    }

    private func policyChanged() {
        hasDispatchedSystemIdle = false
        hasDispatchedConfirmedLock = false
        evaluateAndSchedule()
    }

    @objc private func receiveDistributedSignal(_ notification: Notification) {
        receive(notification.name == Self.screenLocked ? .lockHint : .unlockHint)
    }

    func receive(_ signal: Signal) {
        let now = now()
        switch signal {
        case .sleep:
            lastSleep = now
            enqueue(.systemSleep, at: now)
        case .wake:
            if let lastSleep { enqueue(.systemSleep, at: now, publishedAfter: lastSleep) }
            lastSleep = nil
            evaluateAndSchedule()
        case .activate:
            evaluateAndSchedule()
        case .userSwitch:
            lastUserSwitch = now
            enqueue(.userSwitch, at: now)
        case .returnToUser:
            if let lastUserSwitch { enqueue(.userSwitch, at: now, publishedAfter: lastUserSwitch) }
            lastUserSwitch = nil
            evaluateAndSchedule()
        case .lockHint:
            receiveLockHint(at: now)
        case .unlockHint:
            evaluateAndSchedule()
        }
    }

    private func enqueue(_ trigger: MacSessionTimeoutTrigger, at now: ContinuousClock.Instant,
                         publishedAfter: ContinuousClock.Instant? = nil) {
        systemEvents.append(SystemEvent(trigger: trigger, occurredAt: now, publishedAfter: publishedAfter))
        guard systemEventTask == nil else { return }
        systemEventTask = Task { [weak self] in await self?.drainSystemEvents() }
    }

    private func drainSystemEvents() async {
        defer {
            systemEventTask = nil
            evaluateAndSchedule()
        }
        while !Task.isCancelled {
            await waitForPending()
            guard !systemEvents.isEmpty else { return }
            let event = systemEvents.removeFirst()
            if let lease = await sessionAt(event.occurredAt, event.publishedAfter) {
                request(event.trigger, for: lease, systemEventAt: event.occurredAt)
            }
        }
    }

    func acceptInput() -> Bool {
        guard pending == nil, systemEventTask == nil, lockHintTask == nil, lastUserSwitch == nil else { return false }
        guard let lease = inactivity.lease else { return true }
        let now = now()
        let policy = settings.policy(for: lease.accountID)
        if let remaining = inactivity.timeRemaining(for: policy, at: now), remaining <= .zero,
           request(.appInactivity, for: lease) { return false }
        inactivity.recordInput(at: now)
        if policy.appInactivityDuration != nil, timer == nil { evaluateAndSchedule() }
        return true
    }

    private func receiveLockHint(at now: ContinuousClock.Instant) {
        guard lockHintTask == nil, lastLockHint.map({ $0.duration(to: now) >= .seconds(1) }) != false else { return }
        lastLockHint = now
        if isScreenLocked() {
            confirmScreenLock(at: now)
            return
        }
        lockHintTask = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(150))
            guard !Task.isCancelled, let self else { return }
            lockHintTask = nil
            if isScreenLocked() { confirmScreenLock(at: now) }
            else if !hasDispatchedConfirmedLock { enqueue(.systemLock(confirmed: false), at: now) }
        }
    }

    private func confirmScreenLock(at now: ContinuousClock.Instant) {
        guard !hasDispatchedConfirmedLock else { return }
        hasDispatchedConfirmedLock = true
        enqueue(.systemLock(confirmed: true), at: now)
    }

    private func evaluateAndSchedule() {
        timer?.cancel()
        timer = nil
        guard pending == nil, systemEventTask == nil, let lease = authenticatedLease else { return }
        let policy = settings.policy(for: lease.accountID)
        let next: Duration
        if let remaining = inactivity.timeRemaining(for: policy, at: now()) {
            if remaining <= .zero {
                request(.appInactivity, for: lease)
                return
            }
            next = remaining
        } else if policy.mode == .onSystemIdle {
            let systemIdleSeconds = systemIdleSeconds()
            let threshold = MacSessionTimeoutPolicy.systemIdleSeconds
            if systemIdleSeconds.isFinite, systemIdleSeconds >= threshold {
                if !hasDispatchedSystemIdle {
                    hasDispatchedSystemIdle = true
                    enqueue(.systemIdle, at: now())
                    return
                }
                next = .seconds(15)
            } else {
                hasDispatchedSystemIdle = false
                next = .seconds(systemIdleSeconds.isFinite ? min(15, max(0.25, threshold - systemIdleSeconds)) : 15)
            }
        } else if policy.mode == .onSystemLock {
            if isScreenLocked() {
                if !hasDispatchedConfirmedLock {
                    confirmScreenLock(at: now())
                    return
                }
            } else {
                hasDispatchedConfirmedLock = false
            }
            next = .seconds(2)
        } else {
            return
        }

        timer = Task { [weak self] in
            try? await Task.sleep(for: next, clock: ContinuousClock())
            guard !Task.isCancelled else { return }
            self?.evaluateAndSchedule()
        }
    }

    @discardableResult
    private func request(_ trigger: MacSessionTimeoutTrigger, for lease: AccountSessionLease,
                         systemEventAt: ContinuousClock.Instant? = nil) -> Bool {
        guard pending == nil, let action = settings.policy(for: lease.accountID).action(for: trigger) else { return false }
        timer?.cancel()
        timer = nil
        pending = Task { [weak self, apply] in
            let result = await apply(lease, action, systemEventAt)
            guard let self else { return }
            pending = nil
            if authenticatedLease == lease {
                inactivity.observe(nil, at: now())
                switch result {
                case .superseded, .loggedOut:
                    authenticatedLease = nil
                case .locked, .logoutFailedLocked:
                    authenticatedLease = AccountSessionLease(accountID: lease.accountID, generation: lease.generation &+ 1)
                }
            }
            evaluateAndSchedule()
        }
        return true
    }

    private static func isSessionScreenLocked() -> Bool {
        let session = CGSessionCopyCurrentDictionary() as? [String: Any]
        return session?["CGSSessionScreenIsLocked"] as? Bool == true
    }

    private static func readSystemIdleSeconds() -> TimeInterval {
        CGEventSource.secondsSinceLastEventType(.combinedSessionState, eventType: anyInput)
    }
}
