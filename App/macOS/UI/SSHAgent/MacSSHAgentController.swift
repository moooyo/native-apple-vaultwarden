import AppKit
import CoreGraphics
import Observation
import SwiftUI
import VaultRepository

extension EnvironmentValues {
    @Entry var macSSHAgent: MacSSHAgentController?
}

enum MacSSHAgentSocketMode: String, CaseIterable {
    case openVault, bitwardenDMG
}

@MainActor @Observable
final class MacSSHAgentController: NSObject {
    enum Status: Equatable {
        case disabled, waitingForAccount, ready(String), occupied, compatibilityPathOccupied, compatibilityPathUnavailable, pathTooLong, unavailable
    }

    static let enabledKey = "openvault.mac.sshAgent.enabled"
    static let policyKey = "openvault.mac.sshAgent.policy"
    static let socketModeKey = "openvault.mac.sshAgent.socketMode"
    private static let screenLocked = Notification.Name("com.apple.screenIsLocked")
    private static let screenUnlocked = Notification.Name("com.apple.screenIsUnlocked")

    private(set) var enabled: Bool
    private(set) var policy: MacSSHAgentPolicy
    private(set) var socketMode: MacSSHAgentSocketMode
    private(set) var status = Status.waitingForAccount
    private(set) var itemCount: Int? = 0
    private let consoleGate: ConsoleGate

    @ObservationIgnored private let defaults: UserDefaults
    @ObservationIgnored private let requests: MacSSHAgentRequests
    @ObservationIgnored private let backend: MacSSHAgentRequests.Backend
    @ObservationIgnored private let socketPath: () -> String
    @ObservationIgnored private let bitwardenDMGPath: () -> String?
    @ObservationIgnored private var socket: MacSSHAgentSocket?
    @ObservationIgnored private var listenerID: UUID?
    @ObservationIgnored private var lease: AccountSessionLease?
    @ObservationIgnored private var unlocked = false
    @ObservationIgnored private var nextRefresh: ContinuousClock.Instant?
    @ObservationIgnored private var metadataTask: (id: UUID, task: Task<Void, Never>)?
    @ObservationIgnored private var started = false
    @ObservationIgnored private var terminating = false
    @ObservationIgnored private var observers: [(NotificationCenter, NSObjectProtocol)] = []
    @ObservationIgnored private var systemDistributedObserver: DistributedNotificationCenter?

    init(defaults: UserDefaults = .standard, backend: MacSSHAgentRequests.Backend,
         authenticate: @escaping MacSSHApprovalPanelModel.Authenticate,
         present: @escaping (NSPanel) -> Void = { $0.orderFrontRegardless() },
         socketPath: @escaping () -> String = MacSSHAgentSocket.defaultPath,
         bitwardenDMGPath: @escaping () -> String? = MacSSHAgentSocket.bitwardenDMGPath,
         canOperate: @escaping @MainActor () -> Bool = MacSSHAgentController.canUseConsole) {
        let consoleGate = ConsoleGate(isUsable: canOperate)
        self.consoleGate = consoleGate
        self.defaults = defaults
        self.backend = backend
        self.socketPath = socketPath
        self.bitwardenDMGPath = bitwardenDMGPath
        enabled = defaults.object(forKey: Self.enabledKey) as? Bool ?? true
        policy = defaults.string(forKey: Self.policyKey).flatMap(MacSSHAgentPolicy.init(rawValue:)) ?? .askEveryTime
        socketMode = defaults.string(forKey: Self.socketModeKey).flatMap(MacSSHAgentSocketMode.init(rawValue:)) ?? .openVault
        let prompt = MacSSHAgentPrompt(authenticate: authenticate, present: present)
        requests = MacSSHAgentRequests(backend: backend, approve: prompt.request, complete: prompt.complete,
                                       reject: prompt.reject, canOperate: consoleGate.allowsAccess)
        super.init()
        requests.defaultDuration = policy.defaultDuration
        if !enabled { status = .disabled }
    }

    func start(workspace: NotificationCenter = NSWorkspace.shared.notificationCenter,
               application: NotificationCenter = .default,
               distributed: NotificationCenter = DistributedNotificationCenter.default()) {
        guard !started else { return }
        started = true
        observe(application, NSApplication.willTerminateNotification) { $0.stop() }
        observe(workspace, NSWorkspace.willSleepNotification) { $0.setSleeping(true) }
        observe(workspace, NSWorkspace.didWakeNotification) { $0.setSleeping(false) }
        observe(workspace, NSWorkspace.sessionDidResignActiveNotification) { $0.setConsoleActive(false) }
        observe(workspace, NSWorkspace.sessionDidBecomeActiveNotification) { $0.setConsoleActive(true) }
        observe(application, .NSApplicationProtectedDataWillBecomeUnavailable) { $0.invalidateApprovals() }
        for name in [Self.screenLocked, Self.screenUnlocked] {
            if let system = distributed as? DistributedNotificationCenter {
                system.addObserver(self, selector: #selector(receiveScreenEvent), name: name, object: nil,
                                   suspensionBehavior: .deliverImmediately)
                systemDistributedObserver = system
            } else {
                let locked = name == Self.screenLocked
                observe(distributed, name) { $0.setScreenLocked(locked) }
            }
        }
        update()
    }

    @objc private func receiveScreenEvent(_ notification: Notification) {
        let locked = notification.name == Self.screenLocked
        if Thread.isMainThread {
            setScreenLocked(locked)
        } else {
            Task { @MainActor [weak self] in self?.setScreenLocked(locked) }
        }
    }

    private func setSleeping(_ sleeping: Bool) {
        consoleGate.sleeping = sleeping
        invalidateApprovals()
    }

    private func setConsoleActive(_ active: Bool) {
        consoleGate.active = active
        invalidateApprovals()
    }

    private func setScreenLocked(_ locked: Bool) {
        consoleGate.screenLocked = locked
        invalidateApprovals()
    }

    func sessionDidChange(to lease: AccountSessionLease?, unlocked: Bool) {
        let changed = self.lease != lease || self.unlocked != unlocked
        if changed {
            if self.unlocked && !unlocked { requests.invalidate() }
            cancelMetadataRefresh()
            if self.lease?.accountID != lease?.accountID { itemCount = lease == nil ? 0 : nil }
            self.lease = lease
            self.unlocked = unlocked
            update()
        }
        refreshMetadata()
    }

    func invalidateApprovals() { requests.invalidate() }

    func setEnabled(_ enabled: Bool) {
        guard self.enabled != enabled else { return }
        self.enabled = enabled
        defaults.set(enabled, forKey: Self.enabledKey)
        cancelMetadataRefresh()
        update()
        refreshMetadata()
    }

    func setPolicy(_ policy: MacSSHAgentPolicy) {
        guard self.policy != policy else { return }
        self.policy = policy
        defaults.set(policy.rawValue, forKey: Self.policyKey)
        requests.defaultDuration = policy.defaultDuration
    }

    func setSocketMode(_ mode: MacSSHAgentSocketMode) {
        guard socketMode != mode else { return }
        requests.invalidate()
        closeSocket()
        socketMode = mode
        defaults.set(mode.rawValue, forKey: Self.socketModeKey)
        update()
    }

    var currentSocketPath: String? {
        if case let .ready(path) = status { return path }
        return socketMode == .bitwardenDMG ? bitwardenDMGPath() : socketPath()
    }

    func retry() { update(); refreshMetadata(force: true) }

    func refreshMetadata(force: Bool = false) {
        guard let lease, !terminating, metadataTask == nil,
              force || nextRefresh.map({ .now >= $0 }) != false else { return }
        let id = UUID()
        nextRefresh = ContinuousClock.now.advanced(by: .seconds(2))
        let shouldIndex = enabled && unlocked
        let task = Task { [weak self, backend] in
            defer { if self?.metadataTask?.id == id { self?.metadataTask = nil } }
            if shouldIndex { try? await backend.refreshIndex(lease) }
            guard !Task.isCancelled else { return }
            let count = try? await backend.itemCount(lease)
            guard let self, metadataTask?.id == id, !Task.isCancelled else { return }
            if itemCount != count { itemCount = count }
        }
        metadataTask = (id, task)
    }

    private func cancelMetadataRefresh() {
        metadataTask?.task.cancel()
        metadataTask = nil
        nextRefresh = nil
    }

    private func update() {
        let activeLease = started && enabled && !terminating ? lease : nil
        requests.configure(lease: activeLease)
        guard activeLease != nil else {
            closeSocket(graceful: !terminating)
            status = enabled ? .waitingForAccount : .disabled
            return
        }
        guard socket == nil else { return }
        let compatibilityPath = socketMode == .bitwardenDMG ? bitwardenDMGPath() : nil
        if socketMode == .bitwardenDMG, compatibilityPath == nil {
            status = .compatibilityPathUnavailable
            return
        }
        do {
            let listenerID = UUID()
            let server = try MacSSHAgentSocket(path: socketPath(), compatibilityPath: compatibilityPath) { [weak self] request, peer, destination in
                await self?.receive(request, peer: peer, destination: destination, listenerID: listenerID) ?? .failure
            }
            self.listenerID = listenerID
            socket = server
            status = .ready(compatibilityPath ?? server.path)
        } catch MacSSHAgentSocket.Failure.occupied {
            status = .occupied
        } catch MacSSHAgentSocket.Failure.compatibilityPathOccupied {
            status = .compatibilityPathOccupied
        } catch MacSSHAgentSocket.Failure.compatibilityPathUnavailable {
            status = .compatibilityPathUnavailable
        } catch MacSSHAgentSocket.Failure.invalidPath {
            status = .pathTooLong
        } catch {
            status = .unavailable
        }
    }

    private func receive(_ request: MacSSHAgentProtocol.Request, peer: MacSSHAgentPeer,
                         destination: MacSSHAgentProtocol.Destination, listenerID: UUID) async -> MacSSHAgentSocketReply {
        guard listenerID == self.listenerID else { return .failure }
        return await requests.handle(request, peer: peer, destination: destination)
    }

    private func closeSocket(graceful: Bool = false) {
        listenerID = nil
        if graceful { socket?.stopAfterRejecting() } else { socket?.stop() }
        socket = nil
    }

    private func observe(_ center: NotificationCenter, _ name: Notification.Name,
                         action: @escaping @MainActor @Sendable (MacSSHAgentController) -> Void) {
        let token = center.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { if let self { action(self) } }
        }
        observers.append((center, token))
    }

    private func stop() {
        terminating = true
        cancelMetadataRefresh()
        update()
    }

    isolated deinit {
        for (center, observer) in observers { center.removeObserver(observer) }
        systemDistributedObserver?.removeObserver(self)
        metadataTask?.task.cancel()
        socket?.stop()
    }

    private static func canUseConsole() -> Bool {
        guard let session = CGSessionCopyCurrentDictionary() as? [String: Any] else { return false }
        return session["kCGSSessionOnConsoleKey"] as? Bool == true && session["CGSSessionScreenIsLocked"] as? Bool != true
    }

    @MainActor private final class ConsoleGate {
        var sleeping = false
        var active = true
        var screenLocked = false
        let isUsable: @MainActor () -> Bool

        init(isUsable: @escaping @MainActor () -> Bool) { self.isUsable = isUsable }

        func allowsAccess() -> Bool { !sleeping && active && !screenLocked && isUsable() }
    }
}
