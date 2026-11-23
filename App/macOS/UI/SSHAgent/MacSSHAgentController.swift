import AppKit
import Observation
import SwiftUI
import UIShared
import VaultRepository

extension EnvironmentValues {
    @Entry var macSSHAgent: MacSSHAgentController?
}

@MainActor @Observable
final class MacSSHAgentController {
    enum Status: Equatable {
        case waitingForUnlock
        case ready(String)
        case occupied
        case pathTooLong
        case unavailable
    }

    static let enabledKey = "openvault.mac.sshAgent.enabled"
    static let policyKey = "openvault.mac.sshAgent.policy"

    private(set) var enabled: Bool
    private(set) var policy: MacSSHAgentPolicy
    private(set) var status = Status.waitingForUnlock

    @ObservationIgnored private let defaults: UserDefaults
    @ObservationIgnored private let requests: MacSSHAgentRequests
    @ObservationIgnored private let socketPath: () -> String
    @ObservationIgnored private var socket: MacSSHAgentSocket?
    @ObservationIgnored private var lease: AccountSessionLease?
    @ObservationIgnored private var started = false
    @ObservationIgnored private var terminating = false
    @ObservationIgnored nonisolated(unsafe) private var terminationObserver: (any NSObjectProtocol)?

    init(auth: any AuthService, vault: any VaultService, defaults: UserDefaults = .standard,
         socketPath: @escaping () -> String = MacSSHAgentSocket.defaultPath,
         beforeAccess: @escaping @MainActor () async -> Void = {}) {
        self.defaults = defaults
        self.socketPath = socketPath
        enabled = defaults.bool(forKey: Self.enabledKey)
        policy = defaults.string(forKey: Self.policyKey).flatMap(MacSSHAgentPolicy.init(rawValue:)) ?? .always
        let prompt = MacSSHAgentPrompt()
        requests = MacSSHAgentRequests(backend: .init(auth: auth, vault: vault, beforeAccess: beforeAccess), approve: prompt.request)
    }

    func start() {
        guard !started else { return }
        started = true
        terminationObserver = NotificationCenter.default.addObserver(forName: NSApplication.willTerminateNotification,
                                                                       object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.stop() }
        }
        update()
    }

    func sessionDidChange(to lease: AccountSessionLease?) {
        guard self.lease != lease else { return }
        closeSocket()
        self.lease = lease
        update()
    }

    func setEnabled(_ enabled: Bool) {
        guard self.enabled != enabled else { return }
        self.enabled = enabled
        defaults.set(enabled, forKey: Self.enabledKey)
        update()
    }

    func setPolicy(_ policy: MacSSHAgentPolicy) {
        guard self.policy != policy else { return }
        closeSocket()
        self.policy = policy
        defaults.set(policy.rawValue, forKey: Self.policyKey)
        update()
    }

    func retry() { update() }

    private func update() {
        let activeLease = started && enabled && !terminating ? lease : nil
        requests.configure(lease: activeLease, policy: policy)
        guard activeLease != nil else {
            closeSocket()
            status = .waitingForUnlock
            return
        }
        guard socket == nil else { return }
        let path = socketPath()
        do {
            let server = try MacSSHAgentSocket(path: path) { [weak requests] request, peer in
                await requests?.handle(request, peer: peer) ?? .failure
            }
            socket = server
            status = .ready(server.path)
        } catch MacSSHAgentSocket.Failure.occupied {
            status = .occupied
        } catch MacSSHAgentSocket.Failure.invalidPath {
            status = .pathTooLong
        } catch {
            status = .unavailable
        }
    }

    private func closeSocket() {
        socket?.stop()
        socket = nil
    }

    private func stop() {
        terminating = true
        update()
    }

    deinit {
        if let terminationObserver { NotificationCenter.default.removeObserver(terminationObserver) }
    }
}
