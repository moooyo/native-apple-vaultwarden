import AppKit
import CryptoKit
import Darwin
import Foundation
import VaultRepository

@MainActor
enum MacSSHAgentChecks {
    private nonisolated static let message = Data("Synthetic SSH agent check".utf8)
    private static let originalLease = AccountSessionLease(accountID: "fixture", generation: 1)

    static func run() async throws {
        try checkProtocol()
        try await checkApproval()
        try await checkLockedApproval()
        try await checkSocket()
        try await checkCompatibilityPath()
        try await checkController()
        try await checkPromptPanel()
        print("SSH Agent: verified binding, queued approvals, locked authorization, cache isolation, nonactivating panels and socket modes passed.")
    }

    static func checkNonactivation() async throws {
        try await Task.sleep(for: .milliseconds(200))
        guard let activePID = NSWorkspace.shared.frontmostApplication?.processIdentifier, activePID != getpid() else {
            throw ReviewFailure("a separate foreground app is needed for the nonactivation check")
        }
        var presented: MacSSHApprovalPanel?
        let prompt = MacSSHAgentPrompt(authenticate: { _, _ in .cancelled }, receiptTime: .milliseconds(5)) {
            presented = $0 as? MacSSHApprovalPanel
            $0.orderFrontRegardless()
        }
        let request = Task { await prompt.request(panelApproval(locked: false)) }
        defer { request.cancel(); presented?.orderOut(nil) }
        let window = try await waitForPanel { presented }
        try await Task.sleep(for: .milliseconds(200))
        try require(window.isVisible, "the floating panel is visible")
        try require(!window.isKeyWindow && !NSApp.isActive, "presenting the panel does not make OpenVault active or give it the keyboard")
        let currentPID = NSWorkspace.shared.frontmostApplication?.processIdentifier
        try require(currentPID == activePID, "the foreground application changed during the focus check")
        // Deliver directly to the fixture window. Never synthesize a keystroke into the foreground app.
        guard let input = NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime,
                                           windowNumber: window.windowNumber, context: nil, characters: "\r", charactersIgnoringModifiers: "\r",
                                           isARepeat: false, keyCode: 36) else { throw ReviewFailure("could not create the local key event") }
        window.sendEvent(input)
        try require(window.model.phase == .ask, "Return cannot authorize a non-key approval panel")
        window.close()
        try require(await request.value == nil, "closing the visible window denies the panel")
        print("SSH Agent: the visible floating panel left the foreground application active and ignored Return while not key.")
    }

    private static func checkLockedApproval() async throws {
        let fixture = Fixture(lease: originalLease)
        await fixture.setUnlocked(false)
        let gate = ApprovalGate()
        let requests = MacSSHAgentRequests(backend: fixture.backend, approve: gate.request)
        requests.configure(lease: originalLease)
        let peer = MacSSHAgentPeer()
        let blob = try MacSSHSigningKey.publicKeyBlob(publicKey: fixture.originalIdentity.publicKey)
        let list = await requests.handle(.list, peer: peer)
        try require(try identityBlob(list.packet, count: 2, label: "") == blob, "the locked list never exposes an item name")
        let unknown = await requests.handle(.sign(key: MacSSHKeyEncoding.string("ssh-ed25519"), data: message, flags: 0), peer: peer)
        try require(unknown.packet == .failurePacket && gate.count == 0, "an unknown public key never prompts")
        let sign = MacSSHAgentProtocol.Request.sign(key: blob, data: message, flags: 0)
        let deny = Task { await requests.handle(sign, peer: peer) }
        try await gate.wait(for: 1)
        try require(gate.observed[0].locked, "a bound request uses the locked panel variant")
        gate.resolve(nil)
        let denied = await deny.value
        let unlockedAfterDenial = await fixture.unlocked
        let readsAfterDenial = await fixture.privateReads
        try require(denied.packet == .failurePacket && !unlockedAfterDenial && readsAfterDenial == 0,
                    "denial leaves the vault locked and does not load the key")
        let unauthorized = Task { await requests.handle(sign, peer: peer) }
        try await gate.wait(for: 2)
        gate.resolve(.once)
        try require(await unauthorized.value.packet == .failurePacket, "approval cannot reply until the vault actually unlocks")
        let approve = Task { await requests.handle(sign, peer: peer) }
        try await gate.wait(for: 3)
        await fixture.setUnlocked(true)
        gate.resolve(.once)
        try await verifyAndSend(await approve.value, fixture: fixture)
    }

    private static func checkProtocol() throws {
        try require(MacSSHAgentProtocol.request(Data([11])) == .list, "an exact list request parses")
        try require(MacSSHAgentProtocol.request(Data([11, 0])) == .unsupported, "extra list payload is rejected")
        for type: UInt8 in [17, 18, 19, 20, 21, 22, 23, 25, 26] {
            try require(MacSSHAgentProtocol.request(Data([type])) == .unsupported, "request \(type) cannot modify the vault")
        }
        let key = MacSSHKeyEncoding.string("ssh-ed25519") + MacSSHKeyEncoding.string(Data(repeating: 1, count: 32))
        try require(MacSSHAgentProtocol.request(signPacket(key: key)) == .sign(key: key, data: message, flags: 0),
                    "a well-formed sign request parses")
        try require(MacSSHAgentProtocol.request(signPacket(key: key, flags: 1)) == .unsupported, "unsupported flags fail")
        try require(MacSSHAgentProtocol.request(signPacket(key: key).dropLast()) == .unsupported, "truncated flags fail")
        try require(MacSSHAgentProtocol.request(signPacket(key: key) + Data([0])) == .unsupported, "trailing bytes fail")
        try require(MacSSHAgentProtocol.request(Data([13, 0xFF, 0xFF, 0xFF, 0xFF])) == .unsupported, "huge length fails")
        let host = HostFixture()
        let bind = try host.request()
        try require(MacSSHAgentProtocol.request(bind.packet) == .bind(bind.binding) && bind.binding.isVerified,
                    "a well-formed session-bound request verifies its real host signature")
        let forwarded = try host.request(forwarding: true)
        try require(MacSSHAgentProtocol.request(forwarded.packet) == .rejectedBinding, "forwarded bind closes the connection")
        let invalid = try host.request(invalidSignature: true)
        try require(!invalid.binding.isVerified, "a signature over a different session does not verify")
        let userAuth = host.userAuth(userKey: key)
        try require(bind.binding.matchesUserAuthentication(userAuth, userKey: key, flags: 0), "bound user authentication matches")
        try require(!bind.binding.matchesUserAuthentication(userAuth, userKey: Data([2]), flags: 0), "another user key never inherits the host label")
        try require(!bind.binding.matchesUserAuthentication(userAuth + Data([0]), userKey: key, flags: 0), "trailing userauth data cannot inherit the host label")
        try require(!bind.binding.matchesUserAuthentication(host.userAuth(userKey: key, boundHost: Data([3])), userKey: key, flags: 0),
                    "a mismatched host-bound key cannot inherit the label")
        let pin = "ssh-ed25519 \(host.blob.base64EncodedString())"
        try require(MacSSHKnownHosts(files: ["destination.test \(pin)"]).host(for: host.blob) == "destination.test", "a literal pin gives a name")
        for ambiguous in ["destination.test,alias.test \(pin)", "|1|hash|\(host.blob.count) \(pin)",
                          "@cert-authority destination.test \(pin)", "destination.test \(pin)\n@revoked * \(pin)"] {
            try require(MacSSHKnownHosts(files: [ambiguous]).host(for: host.blob) == nil, "ambiguous or ineligible pins do not give a name")
        }
        try require(MacSSHAgentProtocol.safeLabel("Key\n\u{202e}name") == "Keyname", "prompt labels strip control characters")
        let address = try MacSSHAgentSocket.address("/" + String(repeating: "x", count: 102))
        try require(address.count == 106, "the longest OpenSSH-compatible socket address fits")
        do {
            _ = try MacSSHAgentSocket.address("/" + String(repeating: "x", count: 103))
            throw ReviewFailure("a socket path incompatible with the system SSH client must be rejected")
        } catch MacSSHAgentSocket.Failure.invalidPath {}
    }

    private static func checkApproval() async throws {
        let fixture = Fixture(lease: originalLease)
        let gate = ApprovalGate()
        var now = ContinuousClock.now
        let core = MacSSHAgentRequests(backend: fixture.backend, approve: gate.request, reject: { gate.resolve(nil) }, now: { now })
        let firstPeer = MacSSHAgentPeer(pid: 100, appName: "App", signingIdentity: .init(signer: "team-1", identifier: "org.fixture.app"))
        let sameApp = MacSSHAgentPeer(pid: 101, signingIdentity: firstPeer.signingIdentity)
        let otherApp = MacSSHAgentPeer(pid: 102, appName: "App", signingIdentity: .init(signer: "team-2", identifier: "org.fixture.app"))
        let unverified = MacSSHAgentPeer(pid: 103, appName: "App", chain: ["App", "ssh"])
        let blob = try MacSSHSigningKey.publicKeyBlob(publicKey: fixture.originalIdentity.publicKey)
        let otherBlob = try MacSSHSigningKey.publicKeyBlob(publicKey: fixture.secondIdentity.publicKey)
        let request = MacSSHAgentProtocol.Request.sign(key: blob, data: message, flags: 0)
        core.configure(lease: originalLease)
        let list = await core.handle(.list, peer: firstPeer)
        let validList = await list.validatesOnSend?()
        try require(try identityBlob(list.packet, count: 2) == blob && validList == true && gate.count == 0,
                    "listing returns deduplicated public data without prompting")

        let denied = Task { await core.handle(request, peer: firstPeer) }
        try await gate.wait(for: 1)
        let unknownWhilePending = await core.handle(.sign(key: MacSSHKeyEncoding.string("ssh-ed25519"), data: message, flags: 0), peer: otherApp)
        try require(unknownWhilePending.packet == .failurePacket && gate.count == 1, "unknown keys fail immediately even with a busy panel")
        let queued = Task { await core.handle(request, peer: otherApp) }
        try await Task.sleep(for: .milliseconds(30))
        let pendingReads = await fixture.privateReads
        try require(gate.count == 1 && pendingReads == 0, "the next request waits without reading private keys")
        gate.resolve(nil)
        try require(await denied.value.packet == .failurePacket, "denial returns generic failure")
        try await gate.wait(for: 2)
        try require(gate.observed[1].peer == otherApp, "the queued request is next")
        gate.resolve(.once)
        try await verifyAndSend(await queued.value, fixture: fixture)
        let repeatOnce = Task { await core.handle(request, peer: otherApp) }
        try await gate.wait(for: 3)
        gate.resolve(nil)
        try require(await repeatOnce.value.packet == .failurePacket, "one-time approval is not remembered")

        core.defaultDuration = .minutes15
        let remembered = Task { await core.handle(request, peer: firstPeer) }
        try await gate.wait(for: 4)
        try require(gate.observed[3].defaultDuration == .minutes15, "the policy sets the picker default, not permission")
        gate.resolve(.minutes15)
        try await verifyAndSend(await remembered.value, fixture: fixture)
        now = now.advanced(by: .seconds(899))
        try await verifyAndSend(await core.handle(request, peer: sameApp), fixture: fixture)
        try require(gate.count == 4, "another process of the same signing app can reuse the approval before expiry")
        let distinct = Task { await core.handle(request, peer: otherApp) }
        try await gate.wait(for: 5)
        gate.resolve(nil)
        try require(await distinct.value.packet == .failurePacket, "the same identifier from another signer cannot use consent")
        let differentKey = Task { await core.handle(.sign(key: otherBlob, data: message, flags: 0), peer: sameApp) }
        try await gate.wait(for: 6)
        gate.resolve(nil)
        try require(await differentKey.value.packet == .failurePacket, "a different key cannot use consent")
        let expireBeforeSending = await core.handle(request, peer: sameApp)
        now = now.advanced(by: .seconds(1))
        try require(expireBeforeSending.permitsSignature?() == false, "expiry also fences an unsent signature")
        expireBeforeSending.didComplete?(false)

        let expired = Task { await core.handle(request, peer: firstPeer) }
        try await gate.wait(for: 7)
        gate.resolve(.untilVaultLock)
        try await verifyAndSend(await expired.value, fixture: fixture)
        now = now.advanced(by: .seconds(3_600))
        try await verifyAndSend(await core.handle(request, peer: sameApp), fixture: fixture)
        core.invalidate()
        let afterLock = Task { await core.handle(request, peer: sameApp) }
        try await gate.wait(for: 8)
        let reads = await fixture.privateReads
        await fixture.replaceIdentity()
        gate.resolve(.untilVaultLock)
        let readsAfterMutation = await fixture.privateReads
        try require(await afterLock.value.packet == .failurePacket && readsAfterMutation == reads,
                    "lock clears the cache, and mutation during the new prompt prevents secret access")
        await fixture.restoreIdentity()

        let unsigned = Task { await core.handle(request, peer: unverified) }
        try await gate.wait(for: 9)
        gate.resolve(.untilVaultLock)
        try await verifyAndSend(await unsigned.value, fixture: fixture)
        let unsignedAgain = Task { await core.handle(request, peer: unverified) }
        try await gate.wait(for: 10)
        await fixture.setLease(AccountSessionLease(accountID: "different-account", generation: 2))
        gate.resolve(.once)
        try require(await unsignedAgain.value.packet == .failurePacket, "an unverified peer cannot reuse consent and a stale account cannot sign")
    }

    private static func checkSocket() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("openvault-agent-\(UUID().uuidString.prefix(8))")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let directory = root.appendingPathComponent("private")
        let socketPath = directory.appendingPathComponent("ssh").path
        let fixture = Fixture(lease: originalLease)
        let peers = ApprovalGate(autoApprove: true)
        let requests = MacSSHAgentRequests(backend: fixture.backend, approve: peers.request)
        requests.configure(lease: originalLease)
        let host = HostFixture()
        let server = try MacSSHAgentSocket(path: socketPath, hostLookup: { $0 == host.blob ? "destination.test" : nil }) {
            await requests.handle($0, peer: $1, verifiedHost: $2)
        }
        defer { server.stop() }

        let mode = try FileManager.default.attributesOfItem(atPath: directory.path)[.posixPermissions] as? Int
        let socketMode = try FileManager.default.attributesOfItem(atPath: socketPath)[.posixPermissions] as? Int
        let ownershipMode = try FileManager.default.attributesOfItem(atPath: directory.appendingPathComponent(".ssh-owner").path)[.posixPermissions] as? Int
        try require(mode == 0o700 && socketMode == 0o600 && ownershipMode == 0o600, "directory and socket state have user-only permissions")
        do {
            _ = try MacSSHAgentSocket(path: socketPath) { _, _, _ in .failure }
            throw ReviewFailure("a second listener must not replace an occupied socket")
        } catch MacSSHAgentSocket.Failure.occupied {}

        let publicBlob = try MacSSHSigningKey.publicKeyBlob(publicKey: fixture.originalIdentity.publicKey)
        let invalid = try host.request(invalidSignature: true).packet
        let valid = try host.request().packet
        let forwarding = try host.request(forwarding: true).packet
        let userAuth = host.userAuth(userKey: publicBlob, boundHost: host.blob)
        let packets = try await Task.detached {
            let client = try Client(path: socketPath)
            let rejected = try client.exchange(invalid)
            let list = try client.exchange(Data([11]), fragmented: true)
            let accepted = try client.exchange(valid)
            let first = try client.exchange(signPacket(key: publicBlob, data: userAuth))
            let mismatch = try client.exchange(signPacket(key: publicBlob))
            let unbound = try Client(path: socketPath)
            let second = try unbound.exchange(signPacket(key: publicBlob, data: userAuth))
            let forwarded = try client.exchange(forwarding)
            let forwardedClosed = client.readEnd()
            let oversized = try Client(path: socketPath)
            try oversized.send(MacSSHAgentProtocol.uint32(UInt32(MacSSHAgentProtocol.maximumPacketSize + 1)))
            return (rejected, list, accepted, first, mismatch, second, forwarded, forwardedClosed, oversized.readEnd())
        }.value
        try require(packets.0 == .failurePacket && packets.2 == MacSSHAgentProtocol.success && packets.6 == .failurePacket && packets.7 && packets.8,
                    "the socket accepts a real host signature and rejects invalid signatures, forwarding and oversized frames")
        try require(try identityBlob(packets.1, count: 2) == publicBlob && packets.3.first == 14 && packets.4.first == 14 && packets.5.first == 14,
                    "fragmented frames and separate clients list and sign")
        try require(peers.observed.first?.peer.pid == getpid(), "the displayed peer PID comes from the kernel")
        try require(peers.observed.map(\.verifiedHost) == ["destination.test", nil, nil],
                    "only matching auth on the bound connection inherits the verified host")
        let publicKeyFile = root.appendingPathComponent("fixture.pub")
        try (fixture.originalIdentity.publicKey + "\n").write(to: publicKeyFile, atomically: true, encoding: .utf8)
        let status = try await Task.detached {
            let ssh = Process()
            ssh.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-add")
            ssh.arguments = ["-T", publicKeyFile.path]
            ssh.environment = ["SSH_AUTH_SOCK": socketPath]
            try ssh.run()
            ssh.waitUntilExit()
            return ssh.terminationStatus
        }.value
        try require(status == 0 && peers.count == 4 && peers.observed.last?.peer.signingIdentity == nil,
                    "system OpenSSH signs and verifies a generated key without persisting approval for a CLI helper")

        server.stop()
        try require(!FileManager.default.fileExists(atPath: socketPath), "stop removes only the owned socket")
        try Data("unowned entry".utf8).write(to: URL(fileURLWithPath: socketPath))
        do {
            _ = try MacSSHAgentSocket(path: socketPath) { _, _, _ in .failure }
            throw ReviewFailure("a non-socket file must never be removed")
        } catch MacSSHAgentSocket.Failure.occupied {}
        try require(try Data(contentsOf: URL(fileURLWithPath: socketPath)) == Data("unowned entry".utf8), "existing files survive")

        let stale = directory.appendingPathComponent("old").path
        let staleNode = try bindForRecoveryTest(path: stale)
        do {
            _ = try MacSSHAgentSocket(path: stale) { _, _, _ in .failure }
            throw ReviewFailure("a matching ownership record cannot replace a still listening socket")
        } catch MacSSHAgentSocket.Failure.occupied {}
        close(staleNode)
        let restarted = try MacSSHAgentSocket(path: stale) { _, _, _ in .failure }
        restarted.stop()
        try require(!FileManager.default.fileExists(atPath: stale), "a verified stale socket can be recovered after a crash")
    }

    private static func bindForRecoveryTest(path: String, recordOwnership: Bool = true) throws -> Int32 {
        let address = try MacSSHAgentSocket.address(path)
        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw ReviewFailure("cannot create the recovery socket") }
        var installed = false
        defer { if !installed { close(descriptor) } }
        guard address.withUnsafeBytes({ bind(descriptor, $0.baseAddress?.assumingMemoryBound(to: sockaddr.self), socklen_t($0.count)) }) == 0,
              listen(descriptor, 1) == 0 else { throw ReviewFailure("cannot start the recovery socket") }
        if recordOwnership {
            var node = stat()
            guard lstat(path, &node) == 0 else { throw ReviewFailure("cannot identify the recovery socket") }
            let record = "\(node.st_dev):\(node.st_ino):\(node.st_birthtimespec.tv_sec):\(node.st_birthtimespec.tv_nsec)\n"
            let ownerPath = (path as NSString).deletingLastPathComponent + "/.ssh-owner"
            try record.write(toFile: ownerPath, atomically: false, encoding: .utf8)
        }
        installed = true
        return descriptor
    }

    private static func checkCompatibilityPath() async throws {
        let root = URL(fileURLWithPath: "/tmp").appendingPathComponent("openvault-alias-\(UUID().uuidString.prefix(8))")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let path = root.appendingPathComponent("private/ssh").path
        let dmgPath = root.appendingPathComponent("private/dmg").path
        let alias = root.appendingPathComponent(".bitwarden-ssh-agent.sock").path
        let occupied = try bindForRecoveryTest(path: alias, recordOwnership: false)
        defer { close(occupied) }
        do {
            _ = try MacSSHAgentSocket(path: path, compatibilityPath: alias) { _, _, _ in .failure }
            throw ReviewFailure("an active foreign agent must not be replaced")
        } catch MacSSHAgentSocket.Failure.compatibilityPathOccupied {}
        let foreignClient = try Client(path: alias)
        try require(unlink(alias) == 0, "remove the test's foreign socket after verifying it still accepts connections")

        try require(symlink(dmgPath, alias) == 0, "create a link to the expected target without an ownership record")
        do {
            _ = try MacSSHAgentSocket(path: path, compatibilityPath: alias) { _, _, _ in .failure }
            throw ReviewFailure("a foreign link must not be replaced")
        } catch MacSSHAgentSocket.Failure.compatibilityPathOccupied {}
        try require(try FileManager.default.destinationOfSymbolicLink(atPath: alias) == dmgPath, "the foreign link is unchanged")
        try require(unlink(alias) == 0, "remove the test's foreign link")

        let server = try MacSSHAgentSocket(path: path, compatibilityPath: alias) { request, _, _ in
            request == .list ? .init(packet: MacSSHAgentProtocol.identities([])) : .failure
        }
        defer { server.stop() }
        try require(try FileManager.default.destinationOfSymbolicLink(atPath: alias) == dmgPath && !entryExists(at: path),
                    "the compatibility path points to a separate private socket")
        do {
            _ = try MacSSHAgentSocket(path: path) { _, _, _ in .failure }
            throw ReviewFailure("a second instance must not run a listener in the other mode")
        } catch MacSSHAgentSocket.Failure.occupied {}
        let reply = try await Task.detached { try Client(path: alias).exchange(Data([11])) }.value
        try require(reply == MacSSHAgentProtocol.identities([]), "a client can use the compatibility path as an SSH agent")
        server.stop()
        try require(!entryExists(at: alias) && !entryExists(at: dmgPath), "stopping removes the owned socket and link")

        let replaced = try MacSSHAgentSocket(path: path, compatibilityPath: alias) { _, _, _ in .failure }
        defer { replaced.stop() }
        let moved = root.appendingPathComponent("moved-link").path
        try require(rename(alias, moved) == 0 && symlink(dmgPath, alias) == 0, "replace the link externally with one that has the same target")
        replaced.stop()
        try require(try FileManager.default.destinationOfSymbolicLink(atPath: alias) == dmgPath, "stopping preserves a replacement even if its target is unchanged")
        let regular = try MacSSHAgentSocket(path: path) { _, _, _ in .failure }
        defer { regular.stop() }
        try require((try? Client(path: alias)) == nil, "a dangling DMG alias cannot reach the default listener")
        withExtendedLifetime(foreignClient) {}
    }

    private static func entryExists(at path: String) -> Bool {
        var info = stat()
        return lstat(path, &info) == 0
    }

    private static func checkController() async throws {
        let suite = "org.openvault.ssh-agent-checks.\(UUID().uuidString)"
        guard let defaults = UserDefaults(suiteName: suite) else { throw ReviewFailure("could not isolate SSH agent preferences") }
        defer { defaults.removePersistentDomain(forName: suite) }
        let root = URL(fileURLWithPath: "/tmp").appendingPathComponent("openvault-mode-\(UUID().uuidString.prefix(8))")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let path = root.appendingPathComponent("private/ssh").path
        let dmgPath = root.appendingPathComponent("private/dmg").path
        let alias = root.appendingPathComponent(".bitwarden-ssh-agent.sock").path
        var requestedPath = false
        var requestedAlias = false
        let fixture = Fixture(lease: originalLease)
        var panel: MacSSHApprovalPanel?
        let agent = MacSSHAgentController(defaults: defaults, backend: fixture.backend, authenticate: { _, _ in .cancelled },
                                          present: { panel = $0 as? MacSSHApprovalPanel }, socketPath: {
            requestedPath = true
            return path
        }, bitwardenDMGPath: {
            requestedAlias = true
            return alias
        }, canOperate: { true })
        defer { agent.setEnabled(false) }
        let workspace = NotificationCenter()
        let distributed = NotificationCenter()
        agent.start(workspace: workspace, application: NotificationCenter(), distributed: distributed)
        try require(agent.enabled && agent.policy == .askEveryTime && agent.socketMode == .openVault && !requestedPath && !requestedAlias,
                    "the default-on agent still needs an authenticated account to bind the socket")
        agent.setSocketMode(.bitwardenDMG)
        try require(agent.status == .waitingForAccount && !entryExists(at: alias), "the DMG path isn't published without an account")
        let restored = MacSSHAgentController(defaults: defaults, backend: fixture.backend, authenticate: { _, _ in .cancelled })
        try require(restored.enabled && restored.socketMode == .bitwardenDMG, "the selected path survives a new controller")

        agent.sessionDidChange(to: originalLease, unlocked: false)
        try require(agent.status == .ready(alias) && entryExists(at: alias), "a locked session publishes and displays the DMG path")
        agent.setSocketMode(.openVault)
        try require(agent.status == .ready(path) && !entryExists(at: alias), "switching back removes the DMG entry point")
        let marker = Data("foreign file".utf8)
        try marker.write(to: URL(fileURLWithPath: alias))
        agent.setSocketMode(.bitwardenDMG)
        try require(agent.status == .compatibilityPathOccupied && !entryExists(at: path) && !entryExists(at: dmgPath),
                    "a collision is reported instead of falling back silently")
        try require(try Data(contentsOf: URL(fileURLWithPath: alias)) == marker, "the existing file survives")
        try require(unlink(alias) == 0, "remove the test's foreign file")
        agent.retry()
        try require(agent.status == .ready(alias), "retry works after the path is released")
        agent.setPolicy(.sameApp15Min)
        try require(defaults.string(forKey: MacSSHAgentController.policyKey) == "sameApp15Min", "policies persist in the injected domain")
        let blob = try MacSSHSigningKey.publicKeyBlob(publicKey: fixture.originalIdentity.publicKey)
        for notification in [NSWorkspace.willSleepNotification, Notification.Name("com.apple.screenIsLocked"), nil] {
            panel = nil
            let transaction = Task.detached { try Client(path: alias).exchange(signPacket(key: blob)) }
            let presented = try await waitForPanel { panel }
            let second = Task.detached { try Client(path: alias).exchange(signPacket(key: blob)) }
            try await Task.sleep(for: .milliseconds(50))
            switch notification {
            case NSWorkspace.willSleepNotification: workspace.post(name: NSWorkspace.willSleepNotification, object: nil)
            case let name?: distributed.post(name: name, object: nil)
            case nil: agent.setEnabled(false)
            }
            try require(presented.model.phase == .denied, "sleep, screen lock and disable synchronously show a denial receipt")
            let packets = try await [transaction.value, second.value]
            try require(packets.allSatisfy { $0 == .failurePacket }, "active and queued sockets both receive generic SSH_AGENT_FAILURE")
            if let notification {
                let blocked = try await Task.detached { try Client(path: alias).exchange(signPacket(key: blob)) }.value
                try require(blocked == .failurePacket, "new requests cannot enter while the Mac is asleep or screen-locked")
                if notification == NSWorkspace.willSleepNotification {
                    workspace.post(name: NSWorkspace.didWakeNotification, object: nil)
                } else {
                    distributed.post(name: Notification.Name("com.apple.screenIsUnlocked"), object: nil)
                }
            }
        }
        try require(agent.status == .disabled && !entryExists(at: alias) && !entryExists(at: dmgPath), "disable stops the listener and removes both entry points")
        try require(defaults.object(forKey: MacSSHAgentController.enabledKey) as? Bool == false, "explicit opt-out persists")
    }

    private static func checkPromptPanel() async throws {
        var panel: MacSSHApprovalPanel?
        let prompt = MacSSHAgentPrompt(authenticate: { _, _ in .cancelled }, receiptTime: .milliseconds(5)) {
            panel = $0 as? MacSSHApprovalPanel
        }
        let request = panelApproval(locked: false)
        let initial = Task { await prompt.request(request) }
        let window = try await waitForPanel { panel }
        let size = window.frame.size
        try require(!window.isKeyWindow && window.canBecomeKey && !window.canBecomeMain && window.level == .floating
                    && window.styleMask.contains(.nonactivatingPanel) && !window.styleMask.contains(.titled)
                    && size == CGSize(width: 480, height: 364) && !window.isRestorable && window.isExcludedFromWindowsMenu,
                    "the panel is fixed-size, borderless, nonactivating and floating")
        try require(await prompt.request(panelApproval(locked: true)) == nil, "a live panel cannot be replaced")
        initial.cancel()
        try require(await initial.value == nil && window.model.phase == .denied, "cancelling a request denies the prompt")
        panel = nil
        let next = Task { await prompt.request(panelApproval(locked: true)) }
        let nextWindow = try await waitForPanel { panel }
        try require(nextWindow !== window && nextWindow.frame.size == size, "the locked variant does not resize")
        nextWindow.close()
        try require(await next.value == nil, "closing the standalone prompt denies authorization")
        try await checkPanelStates()
    }

    private static func checkPanelStates() async throws {
        let origin = ContinuousClock.now
        var now = origin
        var results: [MacSSHApprovalDuration?] = []
        var announcements: [String] = []
        let gate = VerificationGate()
        let model = MacSSHApprovalPanelModel(approval: panelApproval(locked: true), authenticate: gate.verify,
                                             decide: { results.append($0) }, now: { now }, announce: { announcements.append($0) })
        model.startCountdown()
        try require(model.countdown(reduceMotion: false).seconds == 30, "the ask state starts a full 30-second countdown")
        now = origin.advanced(by: .seconds(15))
        try require(model.countdown(reduceMotion: false).fraction == 0.5, "the countdown fill shrinks linearly")
        now = origin.advanced(by: .seconds(25))
        try require(model.countdown(reduceMotion: false).warning == 0.5 && model.countdown(reduceMotion: true).warning == 1,
                    "normal and reduced-motion warnings start at the expected thresholds")
        model.approve()
        try await gate.wait(for: 1)
        try require(model.phase == .touch && results.isEmpty, "Approve starts Touch ID without authorizing the request")
        now = origin.advanced(by: .seconds(90))
        gate.finish(.cancelled)
        try await waitUntil { model.phase == .ask }
        try require(model.countdown(reduceMotion: false).seconds == 30, "cancelling validation restarts the full timer")
        model.approve()
        try await gate.wait(for: 2)
        gate.finish(.passwordRequired)
        try await waitUntil { model.phase == .password }
        model.password = "disposable-fixture-value"
        model.submitPassword()
        try await gate.wait(for: 3)
        gate.finish(.passwordRejected)
        try await waitUntil { model.passwordRejected }
        try require(model.password.isEmpty && results.isEmpty, "a failed password is cleared without signing")
        model.password = "another-disposable-value"
        model.submitPassword()
        try await gate.wait(for: 4)
        gate.finish(.verified)
        try await waitUntil { model.isAuthorized }
        try require(results == [.minutes15], "authentication alone authorizes the selected duration")
        let lockedFlags = gate.locked
        try require(lockedFlags == [true, true, true, true], "all factors in a locked panel use the locked flow")
        model.showReceipt(approved: true)
        try require(model.phase == .done(.minutes15) && announcements.contains(macSSHAgentText("Password verification failed")),
                    "the approval receipt is separate from authentication and a failed password is accessible")

        let timeout = MacSSHApprovalPanelModel(approval: panelApproval(locked: false), authenticate: gate.verify,
                                               decide: { results.append($0) }, now: { ContinuousClock.now.advanced(by: .seconds(-31)) },
                                               announce: { _ in })
        timeout.startCountdown()
        try await waitUntil { results.count == 2 }
        try require(results[1] == nil && gate.locked.count == 4, "expiry denies without starting authentication")
        timeout.showReceipt(approved: false)
    }

    static func panelApproval(locked: Bool) -> MacSSHAgentApproval {
        MacSSHAgentApproval(keyName: "GitHub", keyAlgorithm: "ed25519", fingerprint: "SHA256:abc123456789wxyz",
                            verifiedHost: "github.com", peer: .init(commandName: "git", appName: "终端", chain: ["终端", "zsh", "git"],
                                                                   signingIdentity: .init(signer: "fixture", identifier: "fixture.app")),
                            locked: locked, lease: originalLease, defaultDuration: .minutes15)
    }

    private static func waitUntil(_ condition: () -> Bool) async throws {
        for _ in 0..<100 {
            if condition() { return }
            try await Task.sleep(for: .milliseconds(10))
        }
        throw ReviewFailure("timed out waiting for the approval state")
    }

    private static func waitForPanel(_ panel: () -> MacSSHApprovalPanel?) async throws -> MacSSHApprovalPanel {
        for _ in 0..<300 {
            if let panel = panel() { return panel }
            try await Task.sleep(for: .milliseconds(10))
        }
        throw ReviewFailure("the standalone prompt was not created")
    }

    private static func verify(_ result: MacSSHAgentSocketReply, fixture: Fixture) async throws {
        var reader = MacSSHKeyReader(result.packet)
        guard try reader.bytes(1).first == 14 else { throw ReviewFailure("expected a signature reply") }
        var signature = MacSSHKeyReader(try reader.string(maximum: 2048))
        let format = try signature.name()
        let bytes = try signature.string(maximum: 64)
        try require(format == "ssh-ed25519" && reader.isEmpty && signature.isEmpty
                    && fixture.key.publicKey.isValidSignature(bytes, for: message), "signature is valid for the synthetic request")
    }

    private static func verifyAndSend(_ result: MacSSHAgentSocketReply, fixture: Fixture) async throws {
        try await verify(result, fixture: fixture)
        let validated = await result.validatesOnSend?()
        try require(validated == true && result.permitsSignature?() == true, "the signature still has authorization to be sent")
        result.didComplete?(true)
    }

    private nonisolated static func signPacket(key: Data, data: Data = message, flags: UInt32 = 0) -> Data {
        Data([13]) + MacSSHKeyEncoding.string(key) + MacSSHKeyEncoding.string(data) + MacSSHAgentProtocol.uint32(flags)
    }

    private struct HostFixture: Sendable {
        let key = Curve25519.Signing.PrivateKey()
        let session = Data(repeating: 0xAB, count: 32)
        var blob: Data { MacSSHKeyEncoding.string("ssh-ed25519") + MacSSHKeyEncoding.string(key.publicKey.rawRepresentation) }

        func request(forwarding: Bool = false, invalidSignature: Bool = false) throws -> (packet: Data, binding: MacSSHAgentProtocol.SessionBinding) {
            let raw = try key.signature(for: invalidSignature ? MacSSHKeyEncoding.string(session) : session)
            let signature = MacSSHKeyEncoding.string("ssh-ed25519") + MacSSHKeyEncoding.string(raw)
            let packet = Data([27]) + MacSSHKeyEncoding.string("session-bind@openssh.com") + MacSSHKeyEncoding.string(blob)
                + MacSSHKeyEncoding.string(session) + MacSSHKeyEncoding.string(signature) + Data([forwarding ? 1 : 0])
            return (packet, .init(hostKey: blob, sessionID: session, signature: signature))
        }

        func userAuth(userKey: Data, boundHost: Data? = nil) -> Data {
            let method = boundHost == nil ? "publickey" : "publickey-hostbound-v00@openssh.com"
            return MacSSHKeyEncoding.string(session) + Data([50]) + MacSSHKeyEncoding.string("fixture")
                + MacSSHKeyEncoding.string("ssh-connection") + MacSSHKeyEncoding.string(method) + Data([1])
                + MacSSHKeyEncoding.string("ssh-ed25519") + MacSSHKeyEncoding.string(userKey)
                + (boundHost.map(MacSSHKeyEncoding.string) ?? Data())
        }
    }

    private static func identityBlob(_ reply: Data, count: UInt32 = 1, label: String = "Fixture SSH key") throws -> Data {
        var reader = MacSSHKeyReader(reply)
        guard try reader.bytes(1).first == 12, try reader.uint32() == count else { throw ReviewFailure("unexpected public identity count") }
        let publicKey = try reader.string(maximum: 2048)
        try require(try reader.name() == label && (count > 1 || reader.isEmpty), "the list includes only expected public data")
        return publicKey
    }

    private static func require(_ condition: Bool, _ reason: String) throws {
        if !condition { throw ReviewFailure(reason) }
    }

    private struct ReviewFailure: Error, CustomStringConvertible {
        let description: String
        init(_ description: String) { self.description = "SSH Agent: " + description }
    }

    @MainActor private final class ApprovalGate {
        private(set) var observed: [MacSSHAgentApproval] = []
        var count: Int { observed.count }
        private var pending: CheckedContinuation<MacSSHApprovalDuration?, Never>?
        let autoApprove: Bool

        init(autoApprove: Bool = false) { self.autoApprove = autoApprove }

        func request(_ request: MacSSHAgentApproval) async -> MacSSHApprovalDuration? {
            observed.append(request)
            if autoApprove { return .once }
            return await withCheckedContinuation { pending = $0 }
        }

        func resolve(_ approved: MacSSHApprovalDuration?) {
            let continuation = pending
            pending = nil
            continuation?.resume(returning: approved)
        }

        func wait(for count: Int) async throws {
            for _ in 0..<100 {
                if self.count >= count { return }
                try await Task.sleep(for: .milliseconds(10))
            }
            throw ReviewFailure("approval request timed out")
        }
    }

    @MainActor private final class VerificationGate {
        var locked: [Bool] = []
        var pending: CheckedContinuation<MacSSHApprovalPanelModel.Verification, Never>?

        func verify(_ approval: MacSSHAgentApproval, factor: MacSSHApprovalPanelModel.Factor) async -> MacSSHApprovalPanelModel.Verification {
            locked.append(approval.locked)
            return await withCheckedContinuation { pending = $0 }
        }

        func finish(_ result: MacSSHApprovalPanelModel.Verification) {
            let continuation = pending
            pending = nil
            continuation?.resume(returning: result)
        }

        func wait(for count: Int) async throws { try await waitUntil { locked.count == count && pending != nil } }
    }

    static func settingsBackend(itemCount: Int = 0) -> MacSSHAgentRequests.Backend {
        .init(access: { nil }, identities: { _ in [] }, signingKey: { _, _ in throw RepositoryError.locked },
              isCurrent: { _, _ in false }, sign: { _, _, _, _ in throw RepositoryError.locked }, itemCount: { _ in itemCount })
    }

    private actor Fixture {
        let key: Curve25519.Signing.PrivateKey
        let originalIdentity: VaultSSHAgentIdentity
        let secondIdentity: VaultSSHAgentIdentity
        private var lease: AccountSessionLease?
        private var identity: VaultSSHAgentIdentity
        private(set) var unlocked = true
        private(set) var privateReads = 0

        init(lease: AccountSessionLease) {
            let key = Curve25519.Signing.PrivateKey()
            self.key = key
            self.lease = lease
            originalIdentity = Self.identity("fixture-key", key: key)
            secondIdentity = Self.identity("other-key", key: Curve25519.Signing.PrivateKey())
            identity = originalIdentity
        }

        private static func identity(_ id: String, key: Curve25519.Signing.PrivateKey) -> VaultSSHAgentIdentity {
            let format = "ssh-ed25519"
            let publicBlob = MacSSHKeyEncoding.string(format) + MacSSHKeyEncoding.string(key.publicKey.rawRepresentation)
            return .init(id: id, name: "Fixture SSH key", publicKey: "\(format) \(publicBlob.base64EncodedString())", revision: "1")
        }

        nonisolated var backend: MacSSHAgentRequests.Backend {
            .init(access: { await self.access }, identities: { try await self.identities(for: $0) },
                  signingKey: { try await self.seed($0, for: $1) }, isCurrent: { await self.isCurrent($0, for: $1) },
                  sign: { message, _, seed, _ in
                      guard let bytes = Data(base64Encoded: seed) else { throw ReviewFailure("invalid synthetic seed") }
                      let key = try Curve25519.Signing.PrivateKey(rawRepresentation: bytes)
                      return MacSSHKeyEncoding.string("ssh-ed25519") + MacSSHKeyEncoding.string(try key.signature(for: message))
                  })
        }

        private var access: MacSSHAgentRequests.Access? { lease.map { .init(lease: $0, unlocked: unlocked) } }
        func setLease(_ lease: AccountSessionLease?) { self.lease = lease }
        func setUnlocked(_ unlocked: Bool) { self.unlocked = unlocked }
        func restoreIdentity() { identity = originalIdentity }
        func replaceIdentity() {
            identity = .init(id: identity.id, name: identity.name, publicKey: identity.publicKey, revision: "2")
        }

        private func identities(for access: MacSSHAgentRequests.Access) throws -> [VaultSSHAgentIdentity] {
            guard self.access == access else { throw RepositoryError.locked }
            return [identity, .init(id: "unsupported", name: "Other", publicKey: "ssh-unsupported AQ==", revision: "1"), identity, secondIdentity]
        }

        private func seed(_ identity: VaultSSHAgentIdentity, for lease: AccountSessionLease) throws -> String {
            guard isCurrent(identity, for: lease), identity != secondIdentity else { throw RepositoryError.cipherChanged }
            privateReads += 1
            return key.rawRepresentation.base64EncodedString()
        }

        private func isCurrent(_ identity: VaultSSHAgentIdentity, for lease: AccountSessionLease) -> Bool {
            self.lease == lease && unlocked && (self.identity == identity || self.secondIdentity == identity)
        }
    }

    private final class Client {
        let descriptor: Int32

        init(path: String) throws {
            let address = try MacSSHAgentSocket.address(path)
            let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
            guard descriptor >= 0 else { throw ReviewFailure("could not open test socket") }
            var timeout = timeval(tv_sec: 2, tv_usec: 0)
            var noSignal: Int32 = 1
            guard setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout.size(ofValue: timeout))) == 0,
                  setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout.size(ofValue: timeout))) == 0,
                  setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout.size(ofValue: noSignal))) == 0,
                  address.withUnsafeBytes({ buffer in
                      connect(descriptor, buffer.baseAddress?.assumingMemoryBound(to: sockaddr.self), socklen_t(buffer.count))
                  }) == 0 else {
                close(descriptor)
                throw ReviewFailure("could not connect to the isolated test socket")
            }
            self.descriptor = descriptor
        }

        deinit { close(descriptor) }

        func exchange(_ body: Data, fragmented: Bool = false) throws -> Data {
            let prefix = MacSSHAgentProtocol.uint32(UInt32(body.count))
            if fragmented {
                try send(prefix.prefix(1))
                Thread.sleep(forTimeInterval: 0.01)
                try send(prefix.dropFirst() + body)
            } else {
                try send(prefix + body)
            }
            let count = try read(4).reduce(0) { ($0 << 8) | Int($1) }
            guard (1...MacSSHAgentProtocol.maximumPacketSize).contains(count) else { throw ReviewFailure("invalid reply frame length") }
            return try read(count)
        }

        func send(_ data: Data) throws {
            try data.withUnsafeBytes { buffer in
                var offset = 0
                while offset < buffer.count {
                    let written = Darwin.send(descriptor, buffer.baseAddress?.advanced(by: offset), buffer.count - offset, 0)
                    guard written > 0 else { throw ReviewFailure("could not write a test frame") }
                    offset += written
                }
            }
        }

        func readEnd() -> Bool {
            var byte: UInt8 = 0
            return recv(descriptor, &byte, 1, 0) == 0
        }

        private func read(_ count: Int) throws -> Data {
            var data = Data(count: count)
            try data.withUnsafeMutableBytes { (buffer: UnsafeMutableRawBufferPointer) in
                var offset = 0
                while offset < count {
                    let size = recv(descriptor, buffer.baseAddress?.advanced(by: offset), count - offset, 0)
                    guard size > 0 else { throw ReviewFailure("could not read a test reply") }
                    offset += size
                }
            }
            return data
        }
    }
}

private extension Data {
    static var failurePacket: Self { MacSSHAgentProtocol.failure }
}
