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
        try await checkTimeoutBeforeAccess()
        try await checkSocket()
        try await checkCompatibilityPath()
        try await checkController()
        try await checkPromptPanel()
        print("SSH Agent: protocol, peer-scoped approval, lock invalidation, bounded local socket, and optional Bitwarden DMG path passed.")
    }

    private static func checkTimeoutBeforeAccess() async throws {
        let auth = FakeAuthService(unlocked: true)
        let vault = FakeVaultService(stored: [])
        let lease = await auth.transferSession()
        var checks = 0
        let core = MacSSHAgentRequests(backend: .init(auth: auth, vault: vault, beforeAccess: {
            checks += 1
            await auth.lock()
        }), approve: { _ in false })
        core.configure(lease: lease, policy: .never)
        let result = await core.handle(.list, peer: MacSSHAgentPeer(scope: .connection(UUID())))
        try require(lease != nil && checks == 1 && result.packet == .failurePacket,
                    "the real backend enforces a pending deadline before reading the auth lease")
    }

    private static func checkProtocol() throws {
        try require(MacSSHAgentProtocol.request(Data([11])) == .list, "an exact list request parses")
        try require(MacSSHAgentProtocol.request(Data([11, 0])) == .unsupported, "extra list payload is rejected")
        for type: UInt8 in [17, 18, 19, 20, 21, 22, 23, 25, 26] {
            try require(MacSSHAgentProtocol.request(Data([type])) == .unsupported, "request \(type) cannot modify the vault")
        }
        let key = Data([1, 2, 3])
        try require(MacSSHAgentProtocol.request(signPacket(key: key)) == .sign(key: key, data: message, flags: 0),
                    "a well-formed sign request parses")
        try require(MacSSHAgentProtocol.request(signPacket(key: key, flags: 1)) == .unsupported, "unsupported flags fail")
        try require(MacSSHAgentProtocol.request(signPacket(key: key).dropLast()) == .unsupported, "truncated flags fail")
        try require(MacSSHAgentProtocol.request(signPacket(key: key) + Data([0])) == .unsupported, "trailing bytes fail")
        try require(MacSSHAgentProtocol.request(Data([13, 0xFF, 0xFF, 0xFF, 0xFF])) == .unsupported, "huge length fails")
        try require(MacSSHAgentProtocol.request(binding(forwarding: false)) == .unsupported, "legacy local client can continue")
        try require(MacSSHAgentProtocol.request(binding(forwarding: true)) == .rejectedBinding, "forwarded bind closes the connection")
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
        let core = MacSSHAgentRequests(backend: fixture.backend, approve: gate.request)
        let firstPeer = MacSSHAgentPeer(scope: .connection(UUID()))
        let secondPeer = MacSSHAgentPeer(scope: .connection(UUID()))
        let publicBlob = try MacSSHSigningKey.publicKeyBlob(publicKey: fixture.originalIdentity.publicKey)
        let request = MacSSHAgentProtocol.Request.sign(key: publicBlob, data: message, flags: 0)
        core.configure(lease: originalLease, policy: .always)
        let list = await core.handle(.list, peer: firstPeer)
        let listValid = await list.validatesOnSend?()
        try require(try identityBlob(list.packet) == publicBlob && listValid == true,
                    "listing returns deduplicated public data and validates the lease")
        try require(await fixture.privateReads == 0 && gate.count == 0, "listing never requests a private key or prompts")

        let denied = Task { await core.handle(request, peer: firstPeer) }
        try await gate.wait(for: 1)
        try require(await fixture.privateReads == 0, "the pending prompt has not loaded a private key")
        try require(await core.handle(request, peer: secondPeer).packet == .failurePacket, "only one approval can be pending")
        gate.resolve(false)
        let readsAfterDenial = await fixture.privateReads
        try require(await denied.value.packet == .failurePacket && readsAfterDenial == 0, "denial does not sign")

        for count in 2...3 {
            let pending = Task { await core.handle(request, peer: firstPeer) }
            try await gate.wait(for: count)
            gate.resolve(true)
            try await verify(await pending.value, fixture: fixture)
        }

        core.configure(lease: originalLease, policy: .never)
        try await verify(await core.handle(request, peer: firstPeer), fixture: fixture)
        try require(gate.count == 3, "Never authorizes only while the current session is usable")

        core.configure(lease: originalLease, policy: .rememberUntilLock)
        let remembered = Task { await core.handle(request, peer: firstPeer) }
        try await gate.wait(for: 4)
        gate.resolve(true)
        let first = await remembered.value
        try await verify(first, fixture: fixture)
        await first.didSend?()
        try await verify(await core.handle(request, peer: firstPeer), fixture: fixture)
        try require(gate.count == 4, "the same authorized caller can reuse the approval")
        let separate = Task { await core.handle(request, peer: secondPeer) }
        try await gate.wait(for: 5)
        gate.resolve(false)
        try require(await separate.value.packet == .failurePacket, "another caller cannot use a remembered approval")

        let differentRevision = Task { await core.handle(request, peer: secondPeer) }
        try await gate.wait(for: 6)
        let reads = await fixture.privateReads
        await fixture.replaceIdentity()
        gate.resolve(true)
        let readsAfterMutation = await fixture.privateReads
        try require(await differentRevision.value.packet == .failurePacket && readsAfterMutation == reads,
                    "an item update while approving denies the pending sign before private material is loaded")
        await fixture.restoreIdentity()

        let incomplete = await core.handle(request, peer: firstPeer)
        await fixture.replaceIdentity()
        try require(await incomplete.validatesOnSend?() == false, "mutation after signing invalidates the response before sending")
        await fixture.restoreIdentity()

        let pendingLock = Task { await core.handle(request, peer: secondPeer) }
        try await gate.wait(for: 7)
        await fixture.setLease(nil)
        core.configure(lease: nil, policy: .rememberUntilLock)
        gate.resolve(true)
        try require(await pendingLock.value.packet == .failurePacket, "approval cannot survive lock")
        try require(await core.handle(.list, peer: firstPeer).packet == .failurePacket, "a locked vault returns no identities")

        let nextLease = AccountSessionLease(accountID: originalLease.accountID, generation: 2)
        await fixture.setLease(nextLease)
        core.configure(lease: nextLease, policy: .rememberUntilLock)
        let afterUnlock = Task { await core.handle(request, peer: firstPeer) }
        try await gate.wait(for: 8)
        await fixture.setLease(AccountSessionLease(accountID: "another account", generation: 3))
        gate.resolve(true)
        try require(await afterUnlock.value.packet == .failurePacket, "the real lease invalidates approval even before the UI refreshes")
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
        requests.configure(lease: originalLease, policy: .rememberUntilLock)
        let server = try MacSSHAgentSocket(path: socketPath) { await requests.handle($0, peer: $1) }
        defer { server.stop() }

        let mode = try FileManager.default.attributesOfItem(atPath: directory.path)[.posixPermissions] as? Int
        let socketMode = try FileManager.default.attributesOfItem(atPath: socketPath)[.posixPermissions] as? Int
        let ownershipMode = try FileManager.default.attributesOfItem(atPath: directory.appendingPathComponent(".ssh-owner").path)[.posixPermissions] as? Int
        try require(mode == 0o700 && socketMode == 0o600 && ownershipMode == 0o600, "directory and socket state have user-only permissions")
        do {
            _ = try MacSSHAgentSocket(path: socketPath) { _, _ in .failure }
            throw ReviewFailure("a second listener must not replace an occupied socket")
        } catch MacSSHAgentSocket.Failure.occupied {}

        let publicBlob = try MacSSHSigningKey.publicKeyBlob(publicKey: fixture.originalIdentity.publicKey)
        let packets = try await Task.detached {
            let client = try Client(path: socketPath)
            let replyToRejectedExtension = try client.exchange(binding(forwarding: false))
            let list = try client.exchange(Data([11]), fragmented: true)
            let firstSign = try client.exchange(signPacket(key: publicBlob))
            let anotherConnection = try Client(path: socketPath)
            let secondSign = try anotherConnection.exchange(signPacket(key: publicBlob))
            let peerRejected = try client.exchange(binding(forwarding: true))
            let forwardedClosed = client.readEnd()
            let oversized = try Client(path: socketPath)
            try oversized.send(MacSSHAgentProtocol.uint32(UInt32(MacSSHAgentProtocol.maximumPacketSize + 1)))
            return (replyToRejectedExtension, list, firstSign, secondSign, peerRejected, forwardedClosed, oversized.readEnd())
        }.value
        try require(packets.0 == .failurePacket && packets.4 == .failurePacket && packets.5 && packets.6,
                    "the socket rejects extensions, forwarded sessions, and oversized frames")
        try require(try identityBlob(packets.1) == publicBlob && packets.2.first == 14 && packets.3.first == 14,
                    "fragmented frames and separate clients list and sign")
        try require(peers.observed.first?.peer.pid == getpid() && peers.observed.first?.peer.name?.isEmpty == false,
                    "the approval gets the caller identity from the socket, not its payload")
        try require(peers.count == 1, "a verified peer process can reuse approval on another connection")

        server.stop()
        try require(!FileManager.default.fileExists(atPath: socketPath), "stop removes only the owned socket")
        try Data("unowned entry".utf8).write(to: URL(fileURLWithPath: socketPath))
        do {
            _ = try MacSSHAgentSocket(path: socketPath) { _, _ in .failure }
            throw ReviewFailure("a non-socket file must never be removed")
        } catch MacSSHAgentSocket.Failure.occupied {}
        try require(try Data(contentsOf: URL(fileURLWithPath: socketPath)) == Data("unowned entry".utf8), "existing files survive")

        let stale = directory.appendingPathComponent("old").path
        let staleNode = try bindForRecoveryTest(path: stale)
        do {
            _ = try MacSSHAgentSocket(path: stale) { _, _ in .failure }
            throw ReviewFailure("a matching ownership record cannot replace a still listening socket")
        } catch MacSSHAgentSocket.Failure.occupied {}
        close(staleNode)
        let restarted = try MacSSHAgentSocket(path: stale) { _, _ in .failure }
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
            _ = try MacSSHAgentSocket(path: path, compatibilityPath: alias) { _, _ in .failure }
            throw ReviewFailure("an active foreign agent must not be replaced")
        } catch MacSSHAgentSocket.Failure.compatibilityPathOccupied {}
        let foreignClient = try Client(path: alias)
        try require(unlink(alias) == 0, "remove the test's foreign socket after verifying it still accepts connections")

        try require(symlink(dmgPath, alias) == 0, "create a link to the expected target without an ownership record")
        do {
            _ = try MacSSHAgentSocket(path: path, compatibilityPath: alias) { _, _ in .failure }
            throw ReviewFailure("a foreign link must not be replaced")
        } catch MacSSHAgentSocket.Failure.compatibilityPathOccupied {}
        try require(try FileManager.default.destinationOfSymbolicLink(atPath: alias) == dmgPath, "the foreign link is unchanged")
        try require(unlink(alias) == 0, "remove the test's foreign link")

        let server = try MacSSHAgentSocket(path: path, compatibilityPath: alias) { request, _ in
            request == .list ? .init(packet: MacSSHAgentProtocol.identities([])) : .failure
        }
        defer { server.stop() }
        try require(try FileManager.default.destinationOfSymbolicLink(atPath: alias) == dmgPath && !entryExists(at: path),
                    "the compatibility path points to a separate private socket")
        do {
            _ = try MacSSHAgentSocket(path: path) { _, _ in .failure }
            throw ReviewFailure("a second instance must not run a listener in the other mode")
        } catch MacSSHAgentSocket.Failure.occupied {}
        let reply = try await Task.detached { try Client(path: alias).exchange(Data([11])) }.value
        try require(reply == MacSSHAgentProtocol.identities([]), "a client can use the compatibility path as an SSH agent")
        server.stop()
        try require(!entryExists(at: alias) && !entryExists(at: dmgPath), "stopping removes the owned socket and link")

        let replaced = try MacSSHAgentSocket(path: path, compatibilityPath: alias) { _, _ in .failure }
        defer { replaced.stop() }
        let moved = root.appendingPathComponent("moved-link").path
        try require(rename(alias, moved) == 0 && symlink(dmgPath, alias) == 0, "replace the link externally with one that has the same target")
        replaced.stop()
        try require(try FileManager.default.destinationOfSymbolicLink(atPath: alias) == dmgPath, "stopping preserves a replacement even if its target is unchanged")
        let regular = try MacSSHAgentSocket(path: path) { _, _ in .failure }
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
        let auth = FakeAuthService(unlocked: true)
        let vault = FakeVaultService(stored: [])
        let agent = MacSSHAgentController(auth: auth, vault: vault, defaults: defaults, socketPath: {
            requestedPath = true
            return path
        }, bitwardenDMGPath: {
            requestedAlias = true
            return alias
        })
        defer { agent.setEnabled(false) }
        agent.start()
        let lease = await auth.transferSession()
        try require(lease != nil, "the fixture has an unlocked lease")
        agent.sessionDidChange(to: lease)
        try require(!agent.enabled && agent.policy == .always && agent.socketMode == .openVault && !requestedPath && !requestedAlias,
                    "default-off never resolves or binds a socket path")
        agent.sessionDidChange(to: nil)
        agent.setEnabled(true)
        agent.setSocketMode(.bitwardenDMG)
        try require(agent.status == .waitingForUnlock && !requestedPath && !requestedAlias && !entryExists(at: alias),
                    "selecting the DMG path while locked does not publish it")
        let restored = MacSSHAgentController(auth: auth, vault: vault, defaults: defaults)
        try require(restored.enabled && restored.socketMode == .bitwardenDMG, "the opt-in survives a new controller")

        agent.sessionDidChange(to: lease)
        try require(agent.status == .ready(alias) && entryExists(at: alias), "unlock publishes and displays the DMG path")
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
        agent.setPolicy(.never)
        try require(defaults.bool(forKey: MacSSHAgentController.enabledKey)
                    && defaults.string(forKey: MacSSHAgentController.policyKey) == "never", "policies persist in the injected domain")
        agent.sessionDidChange(to: nil)
        try require(agent.status == .waitingForUnlock && !entryExists(at: alias) && !entryExists(at: dmgPath), "lock closes both entry points")
    }

    private static func checkPromptPanel() async throws {
        var panel: NSPanel?
        let prompt = MacSSHAgentPrompt { panel = $0 }
        let peer = MacSSHAgentPeer(scope: .connection(UUID()), pid: getpid(), name: "SyntheticCaller")
        let request = MacSSHAgentApproval(keyName: "Synthetic vault key", peer: peer)
        let initial = Task { await prompt.request(request) }
        let window = try await waitForPanel { panel }
        try require(!window.isVisible && window.canBecomeKey && window.level == .modalPanel && !window.isRestorable
                    && window.isExcludedFromWindowsMenu && window.contentView != nil,
                    "the prompt is an independent non-restorable panel that can receive approval without a vault window")
        try require(await !prompt.request(request), "a live panel cannot be replaced by a second request")
        panel = nil
        initial.cancel()
        try require(await !initial.value, "cancelling the signing request dismisses the prompt")
        let next = Task { await prompt.request(request) }
        let nextWindow = try await waitForPanel { panel }
        try require(nextWindow !== window, "the next request creates a new panel")
        nextWindow.close()
        try require(await !next.value, "closing the standalone prompt denies authorization")
    }

    private static func waitForPanel(_ panel: () -> NSPanel?) async throws -> NSPanel {
        for _ in 0..<100 {
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

    private nonisolated static func signPacket(key: Data, flags: UInt32 = 0) -> Data {
        Data([13]) + MacSSHKeyEncoding.string(key) + MacSSHKeyEncoding.string(message) + MacSSHAgentProtocol.uint32(flags)
    }

    private nonisolated static func binding(forwarding: Bool) -> Data {
        Data([27]) + MacSSHKeyEncoding.string("session-bind@openssh.com") + MacSSHKeyEncoding.string(Data([1]))
            + MacSSHKeyEncoding.string(Data([2])) + MacSSHKeyEncoding.string(Data([3])) + Data([forwarding ? 1 : 0])
    }

    private static func identityBlob(_ reply: Data) throws -> Data {
        var reader = MacSSHKeyReader(reply)
        guard try reader.bytes(1).first == 12, try reader.uint32() == 1 else { throw ReviewFailure("expected one public identity") }
        let publicKey = try reader.string(maximum: 2048)
        let label = try reader.name()
        try require(label == "Fixture SSH key" && reader.isEmpty, "the identity includes a sanitized public label")
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
        private var pending: CheckedContinuation<Bool, Never>?
        let autoApprove: Bool

        init(autoApprove: Bool = false) { self.autoApprove = autoApprove }

        func request(_ request: MacSSHAgentApproval) async -> Bool {
            observed.append(request)
            if autoApprove { return true }
            return await withCheckedContinuation { pending = $0 }
        }

        func resolve(_ approved: Bool) {
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

    private actor Fixture {
        let key: Curve25519.Signing.PrivateKey
        let originalIdentity: VaultSSHAgentIdentity
        private var lease: AccountSessionLease?
        private var identity: VaultSSHAgentIdentity
        private(set) var privateReads = 0

        init(lease: AccountSessionLease) {
            let key = Curve25519.Signing.PrivateKey()
            let format = "ssh-ed25519"
            let publicBlob = MacSSHKeyEncoding.string(format) + MacSSHKeyEncoding.string(key.publicKey.rawRepresentation)
            self.key = key
            self.lease = lease
            originalIdentity = .init(id: "fixture-key", name: "Fixture SSH key", publicKey: "\(format) \(publicBlob.base64EncodedString())", revision: "1")
            identity = originalIdentity
        }

        nonisolated var backend: MacSSHAgentRequests.Backend {
            .init(session: { await self.lease }, identities: { try await self.identities(for: $0) },
                  signingKey: { try await self.seed($0, for: $1) }, isCurrent: { await self.isCurrent($0, for: $1) },
                  sign: { message, _, seed, _ in
                      guard let bytes = Data(base64Encoded: seed) else { throw ReviewFailure("invalid synthetic seed") }
                      let key = try Curve25519.Signing.PrivateKey(rawRepresentation: bytes)
                      return MacSSHKeyEncoding.string("ssh-ed25519") + MacSSHKeyEncoding.string(try key.signature(for: message))
                  })
        }

        func setLease(_ lease: AccountSessionLease?) { self.lease = lease }
        func restoreIdentity() { identity = originalIdentity }
        func replaceIdentity() {
            identity = .init(id: identity.id, name: identity.name, publicKey: identity.publicKey, revision: "2")
        }

        private func identities(for lease: AccountSessionLease) throws -> [VaultSSHAgentIdentity] {
            guard self.lease == lease else { throw RepositoryError.locked }
            return [identity, .init(id: "unsupported", name: "Other", publicKey: "ssh-unsupported AQ==", revision: "1"), identity]
        }

        private func seed(_ identity: VaultSSHAgentIdentity, for lease: AccountSessionLease) throws -> String {
            guard isCurrent(identity, for: lease) else { throw RepositoryError.cipherChanged }
            privateReads += 1
            return key.rawRepresentation.base64EncodedString()
        }

        private func isCurrent(_ identity: VaultSSHAgentIdentity, for lease: AccountSessionLease) -> Bool {
            self.lease == lease && self.identity == identity
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
