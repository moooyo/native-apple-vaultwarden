import Darwin
import Foundation
import os

struct MacSSHAgentSocketReply: Sendable {
    let packet: Data
    var validatesOnSend: (@Sendable () async -> Bool)?
    var permitsSignature: (@MainActor @Sendable () -> Bool)?
    var didComplete: (@MainActor @Sendable (Bool) -> Void)?

    static let failure = Self(packet: MacSSHAgentProtocol.failure)
}

final class MacSSHAgentSocket: Sendable {
    enum Failure: Error, Equatable {
        case invalidPath
        case unsafeDirectory
        case occupied
        case compatibilityPathOccupied
        case compatibilityPathUnavailable
        case socketUnavailable
    }

    typealias Handler = @Sendable (MacSSHAgentProtocol.Request, MacSSHAgentPeer, String?) async -> MacSSHAgentSocketReply
    typealias HostLookup = @Sendable (Data) -> String?

    let path: String
    private let fileDescriptor: Int32
    private let source: any DispatchSourceRead
    private let state = OSAllocatedUnfairLock(initialState: State())
    private let node: Node
    private let ownership: Int32
    private let modeLock: Int32
    private let compatibilityLink: CompatibilityLink?
    private let handler: Handler
    private let hostLookup: HostLookup

    private static let maximumConnections = 8
    private static let maximumPacketsPerConnection = 96
    private static let ioTimeout: Duration = .seconds(3)
    private static let idleTimeout: Duration = .seconds(30)

    private struct State: Sendable {
        var stopped = false
        var accepting = true
        var connections: [Int32: Task<Void, Never>] = [:]
    }

    private struct Node: Equatable, Sendable {
        let device: dev_t
        let inode: ino_t
        let createdSeconds: Int
        let createdNanoseconds: Int

        init(_ info: stat) {
            device = info.st_dev
            inode = info.st_ino
            createdSeconds = info.st_birthtimespec.tv_sec
            createdNanoseconds = info.st_birthtimespec.tv_nsec
        }

        static func current(at path: String, type: mode_t = mode_t(S_IFSOCK)) -> Node? {
            var info = stat()
            guard lstat(path, &info) == 0,
                  (info.st_mode & S_IFMT) == type, info.st_uid == geteuid() else { return nil }
            return Node(info)
        }
    }

    private struct CompatibilityLink: Sendable {
        let path: String
        let socketPath: String
        let recordPath: String
        let node: Node

        // The listener remains in the sandbox. The only external file we create is
        // this link, and we never replace an entry we cannot prove we created.
        init(path: String, socketPath: String, recordPath: String) throws {
            let link: Node
            if symlink(socketPath, path) == 0 {
                guard let created = Self.ownedLink(at: path, to: socketPath) else {
                    throw Failure.compatibilityPathUnavailable
                }
                do {
                    try MacSSHAgentSocket.recordedOwnership(created).write(to: URL(fileURLWithPath: recordPath), options: .atomic)
                } catch {
                    if Self.ownedLink(at: path, to: socketPath) == created { _ = unlink(path) }
                    throw Failure.compatibilityPathUnavailable
                }
                link = created
            } else {
                guard errno == EEXIST else { throw Failure.compatibilityPathUnavailable }
                guard let existing = Self.ownedLink(at: path, to: socketPath),
                      Self.savedRecord(at: recordPath) == MacSSHAgentSocket.recordedOwnership(existing),
                      Self.ownedLink(at: path, to: socketPath) == existing else {
                    throw Failure.compatibilityPathOccupied
                }
                link = existing
            }
            self.path = path
            self.socketPath = socketPath
            self.recordPath = recordPath
            self.node = link
        }

        func remove() {
            guard Self.ownedLink(at: path, to: socketPath) == node, unlink(path) == 0 else { return }
            _ = unlink(recordPath)
        }

        private static func ownedLink(at path: String, to socketPath: String) -> Node? {
            guard let node = Node.current(at: path, type: mode_t(S_IFLNK)) else { return nil }
            let target = Array(socketPath.utf8)
            var buffer = [UInt8](repeating: 0, count: target.count + 1)
            let count = buffer.withUnsafeMutableBytes { readlink(path, $0.baseAddress!, $0.count) }
            guard count == target.count, buffer.prefix(count).elementsEqual(target) else { return nil }
            return node
        }

        private static func savedRecord(at path: String) -> Data? {
            let descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
            guard descriptor >= 0 else { return nil }
            defer { close(descriptor) }
            var info = stat()
            guard fstat(descriptor, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
                  info.st_uid == geteuid(), (1...96).contains(info.st_size) else { return nil }
            var bytes = [UInt8](repeating: 0, count: Int(info.st_size))
            let count = bytes.withUnsafeMutableBytes { Darwin.read(descriptor, $0.baseAddress, $0.count) }
            guard count == bytes.count else { return nil }
            return Data(bytes)
        }
    }

    static func defaultPath() -> String {
        (NSHomeDirectory() as NSString).appendingPathComponent(".openvault/ssh")
    }

    static func bitwardenDMGPath() -> String? {
        // Foundation's home-directory APIs return the container for a sandboxed app.
        guard let entry = getpwuid(geteuid()), let bytes = entry.pointee.pw_dir,
              let home = String(validatingCString: bytes), home.hasPrefix("/") else { return nil }
        return (home as NSString).appendingPathComponent(".bitwarden-ssh-agent.sock")
    }

    init(path privatePath: String, compatibilityPath: String? = nil,
         hostLookup: @escaping HostLookup = { MacSSHKnownHosts.systemPins().host(for: $0) }, handler: @escaping Handler) throws {
        let directory = (privatePath as NSString).deletingLastPathComponent
        let path: String
        let ownershipName: String
        if let compatibilityPath {
            _ = try Self.address(compatibilityPath)
            // A link left behind by a crash must not expose the default listener.
            path = (directory as NSString).appendingPathComponent("dmg")
            ownershipName = ".ssh-dmg-owner"
        } else {
            path = privatePath
            ownershipName = ".ssh-owner"
        }
        self.path = path
        self.handler = handler
        self.hostLookup = hostLookup
        let address = try Self.address(path)
        try Self.prepareDirectory(directory)
        let modeLock = try Self.lockOwnership(in: directory, name: ".ssh-listener-lock")
        var keepModeLock = false
        defer { if !keepModeLock { close(modeLock) } }
        let ownership = try Self.lockOwnership(in: directory, name: ownershipName)
        var ownsPath = false
        defer { if !ownsPath { close(ownership) } }
        try Self.clearStaleSocket(at: path, address: address, ownership: ownership)
        let listener = socket(AF_UNIX, SOCK_STREAM, 0)
        guard listener >= 0 else { throw Failure.socketUnavailable }
        var listening = false
        defer { if !listening { close(listener) } }
        guard Self.configure(listener) else { throw Failure.socketUnavailable }
        let bound = address.withUnsafeBytes { buffer in
            bind(listener, buffer.baseAddress?.assumingMemoryBound(to: sockaddr.self), socklen_t(buffer.count))
        }
        guard bound == 0 else {
            throw errno == EADDRINUSE ? Failure.occupied : Failure.socketUnavailable
        }
        guard let created = Node.current(at: path) else { throw Failure.socketUnavailable }
        defer { if !listening, Node.current(at: path) == created { unlink(path) } }
        guard chmod(path, 0o600) == 0, listen(listener, Int32(Self.maximumConnections)) == 0 else {
            throw Failure.socketUnavailable
        }
        try Self.remember(created, in: ownership)
        compatibilityLink = try compatibilityPath.map {
            try CompatibilityLink(path: $0, socketPath: path, recordPath: (directory as NSString).appendingPathComponent(".ssh-alias-owner"))
        }
        fileDescriptor = listener
        node = created
        self.ownership = ownership
        self.modeLock = modeLock
        source = DispatchSource.makeReadSource(fileDescriptor: listener, queue: DispatchQueue(label: "org.openvault.ssh-listener"))
        source.setCancelHandler { close(listener) }
        source.setEventHandler { [weak self] in self?.acceptConnections() }
        ownsPath = true
        keepModeLock = true
        listening = true
        source.resume()
    }

    deinit { stop() }

    @MainActor func stopAfterRejecting() {
        // Stop accepting synchronously but allow pending handlers to send their generic
        // failure replies. stop() still runs if the process or controller is torn down.
        stopAccepting()
        Task { [self] in
            try? await Task.sleep(for: .milliseconds(300))
            stop()
        }
    }

    func stop() {
        let tasks = state.withLock { values -> [Task<Void, Never>]? in
            guard !values.stopped else { return nil }
            values.stopped = true
            for descriptor in values.connections.keys { shutdown(descriptor, SHUT_RDWR) }
            return Array(values.connections.values)
        }
        guard let tasks else { return }
        for task in tasks { task.cancel() }
        stopAccepting()
    }

    private func stopAccepting() {
        state.withLock { values in
            guard values.accepting else { return }
            values.accepting = false
            compatibilityLink?.remove()
            if Node.current(at: path) == node, unlink(path) == 0 { _ = ftruncate(ownership, 0) }
            close(ownership)
            close(modeLock)
            source.cancel()
        }
    }

    private func acceptConnections() {
        for _ in 0..<Self.maximumConnections {
            let accepted = state.withLock { values in
                guard values.accepting, !values.stopped else { return false }
                let client = accept(fileDescriptor, nil, nil)
                guard client >= 0 else { return errno == EINTR }
                guard values.connections.count < Self.maximumConnections, Self.accepts(client), Self.configure(client) else {
                    close(client)
                    return true
                }
                let owner = MacSSHAgentPeer.SocketOwner(client)
                values.connections[client] = Task.detached { [weak self, handler, hostLookup] in
                    defer { if let self { self.finish(client) } else { close(client) } }
                    await Self.handle(client, initialOwner: owner, hostLookup: hostLookup, handler: handler)
                }
                return true
            }
            if !accepted { return }
        }
    }

    private func finish(_ descriptor: Int32) {
        state.withLock { values in
            values.connections.removeValue(forKey: descriptor)
            close(descriptor)
        }
    }

    private static func accepts(_ descriptor: Int32) -> Bool {
        var uid: uid_t = 0
        var group: gid_t = 0
        return getpeereid(descriptor, &uid, &group) == 0 && uid == geteuid()
    }

    private static func configure(_ descriptor: Int32) -> Bool {
        let flags = fcntl(descriptor, F_GETFL)
        var noSignal: Int32 = 1
        return flags >= 0
            && fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0
            && fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0
            && setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout.size(ofValue: noSignal))) == 0
    }

    private static func handle(_ descriptor: Int32, initialOwner: MacSSHAgentPeer.SocketOwner?,
                               hostLookup: HostLookup, handler: @escaping Handler) async {
        var binding: MacSSHAgentProtocol.SessionBinding?
        let clock = ContinuousClock()
        for _ in 0..<maximumPacketsPerConnection {
            guard !Task.isCancelled, let first = await read(1, from: descriptor, until: clock.now.advanced(by: idleTimeout)) else { return }
            let deadline = clock.now.advanced(by: ioTimeout)
            guard let rest = await read(3, from: descriptor, until: deadline) else { return }
            let count = (first + rest).reduce(0) { ($0 << 8) | Int($1) }
            guard (1...MacSSHAgentProtocol.maximumPacketSize).contains(count),
                  let packet = await read(count, from: descriptor, until: deadline) else { return }
            let request = MacSSHAgentProtocol.request(packet)
            let reply: MacSSHAgentSocketReply
            var signedPeer: MacSSHAgentPeer.SigningIdentity?
            var close = false
            switch request {
            case let .bind(candidate):
                if let binding {
                    close = binding != candidate
                    reply = close ? .failure : .init(packet: MacSSHAgentProtocol.success)
                } else if candidate.isVerified {
                    binding = candidate
                    reply = .init(packet: MacSSHAgentProtocol.success)
                } else {
                    reply = .failure
                }
            case .rejectedBinding:
                close = true
                reply = .failure
            case let .sign(key, message, flags):
                var host: String?
                if let binding, binding.matchesUserAuthentication(message, userKey: key, flags: flags) {
                    host = hostLookup(binding.hostKey)
                }
                let peer = await MacSSHAgentPeer.read(from: descriptor, initialOwner: initialOwner)
                signedPeer = peer.signingIdentity
                reply = await handleSign(request, descriptor: descriptor, peer: peer, host: host, handler: handler)
            case .list:
                reply = await handler(request, .init(), nil)
            case .unsupported:
                reply = .failure
            }

            let validated = !Task.isCancelled ? await reply.validatesOnSend?() ?? true : false
            var sentSignature = false
            var canContinue = !Task.isCancelled
            if canContinue, validated, reply.packet.first == 14 {
                let framed = frame(reply.packet)
                let expectedSigner = signedPeer
                // The final generation/expiry check and the nonblocking write must not
                // interleave with a disable or lifecycle revocation on the main actor.
                let result = await MainActor.run { () -> (permitted: Bool, sent: Bool) in
                    guard !Task.isCancelled, reply.permitsSignature?() == true,
                          expectedSigner == nil || MacSSHAgentPeer.SocketOwner(descriptor) == initialOwner && initialOwner?.matchesLiveExecutable == true
                    else { return (false, false) }
                    let written = framed.withUnsafeBytes { send(descriptor, $0.baseAddress, $0.count, 0) }
                    return (true, written == framed.count)
                }
                sentSignature = result.sent
                if result.permitted { canContinue = result.sent }
                else { canContinue = await write(frame(MacSSHAgentProtocol.failure), to: descriptor, until: clock.now.advanced(by: ioTimeout)) }
            } else if canContinue {
                let response = validated ? reply.packet : MacSSHAgentProtocol.failure
                canContinue = await write(frame(response), to: descriptor, until: clock.now.advanced(by: ioTimeout))
            }
            await reply.didComplete?(sentSignature)
            if !canContinue || close { return }
        }
    }

    private static func handleSign(_ request: MacSSHAgentProtocol.Request, descriptor: Int32, peer: MacSSHAgentPeer,
                                   host: String?, handler: @escaping Handler) async -> MacSSHAgentSocketReply {
        let operation = Task { await handler(request, peer, host) }
        let watcher = Task {
            while !Task.isCancelled {
                do { try await Task.sleep(for: .milliseconds(200)) } catch { return }
                var status = pollfd(fd: descriptor, events: 0, revents: 0)
                if poll(&status, 1, 0) > 0 && status.revents & Int16(POLLERR | POLLHUP | POLLNVAL) != 0 {
                    operation.cancel()
                    return
                }
            }
        }
        let reply = await withTaskCancellationHandler { await operation.value } onCancel: { operation.cancel() }
        watcher.cancel()
        await watcher.value
        return reply
    }

    private static func frame(_ body: Data) -> Data {
        MacSSHAgentProtocol.uint32(UInt32(body.count)) + body
    }

    private static let ioQueue = DispatchQueue(label: "org.openvault.ssh-io", qos: .userInitiated, attributes: .concurrent)

    private static func read(_ count: Int, from descriptor: Int32, until deadline: ContinuousClock.Instant) async -> Data? {
        await withCheckedContinuation { continuation in
            ioQueue.async { continuation.resume(returning: readBlocking(count, from: descriptor, until: deadline)) }
        }
    }

    private static func readBlocking(_ count: Int, from descriptor: Int32, until deadline: ContinuousClock.Instant) -> Data? {
        var data = Data(count: count)
        let success = data.withUnsafeMutableBytes { buffer in
            transfer(descriptor, count: count, event: Int16(POLLIN), until: deadline) { offset in
                recv(descriptor, buffer.baseAddress?.advanced(by: offset), count - offset, 0)
            }
        }
        return success ? data : nil
    }

    private static func write(_ data: Data, to descriptor: Int32, until deadline: ContinuousClock.Instant) async -> Bool {
        await withCheckedContinuation { continuation in
            ioQueue.async { continuation.resume(returning: writeBlocking(data, to: descriptor, until: deadline)) }
        }
    }

    private static func writeBlocking(_ data: Data, to descriptor: Int32, until deadline: ContinuousClock.Instant) -> Bool {
        data.withUnsafeBytes { buffer in
            transfer(descriptor, count: data.count, event: Int16(POLLOUT), until: deadline) { offset in
                send(descriptor, buffer.baseAddress?.advanced(by: offset), data.count - offset, 0)
            }
        }
    }

    private static func transfer(_ descriptor: Int32, count: Int, event: Int16, until deadline: ContinuousClock.Instant,
                                 perform: (Int) -> Int) -> Bool {
        var offset = 0
        while offset < count {
            let remaining = ContinuousClock().now.duration(to: deadline).components
            let milliseconds = remaining.seconds * 1_000 + remaining.attoseconds / 1_000_000_000_000_000
            guard milliseconds > 0 else { return false }
            let result = perform(offset)
            if result > 0 { offset += result; continue }
            if result == 0 { return false }
            if errno == EINTR { continue }
            guard errno == EAGAIN || errno == EWOULDBLOCK else { return false }
            var info = pollfd(fd: descriptor, events: event, revents: 0)
            let polled = poll(&info, 1, Int32(clamping: milliseconds))
            guard polled > 0 || (polled == -1 && errno == EINTR) else { return false }
        }
        return true
    }

    private static func prepareDirectory(_ directory: String) throws {
        if mkdir(directory, 0o700) != 0, errno != EEXIST { throw Failure.unsafeDirectory }
        var statInfo = stat()
        guard lstat(directory, &statInfo) == 0, statInfo.st_uid == geteuid(),
              (statInfo.st_mode & S_IFMT) == S_IFDIR, (statInfo.st_mode & 0o777) == 0o700 else {
            throw Failure.unsafeDirectory
        }
    }

    private static func lockOwnership(in directory: String, name: String) throws -> Int32 {
        let path = (directory as NSString).appendingPathComponent(name)
        let descriptor = open(path, O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0o600)
        guard descriptor >= 0 else { throw Failure.unsafeDirectory }
        var info = stat()
        guard fstat(descriptor, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
              info.st_uid == geteuid(), (info.st_mode & 0o777) == 0o600, info.st_nlink == 1 else {
            close(descriptor)
            throw Failure.unsafeDirectory
        }
        guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
            let occupied = errno == EWOULDBLOCK
            close(descriptor)
            throw occupied ? Failure.occupied : Failure.socketUnavailable
        }
        return descriptor
    }

    private static func clearStaleSocket(at path: String, address: Data, ownership: Int32) throws {
        var existing = stat()
        if lstat(path, &existing) != 0 {
            guard errno == ENOENT else { throw Failure.socketUnavailable }
            return
        }
        guard let node = Node.current(at: path), node == Node(existing) else { throw Failure.occupied }
        var record = [UInt8](repeating: 0, count: 96)
        let size = record.withUnsafeMutableBytes { pread(ownership, $0.baseAddress, $0.count, 0) }
        guard size > 0, recordedOwnership(node) == Data(record.prefix(size)),
              isNotListening(address), Node.current(at: path) == node,
              unlink(path) == 0 else { throw Failure.occupied }
    }

    private static func remember(_ node: Node, in ownership: Int32) throws {
        let record = recordedOwnership(node)
        guard ftruncate(ownership, 0) == 0,
              record.withUnsafeBytes({ pwrite(ownership, $0.baseAddress, $0.count, 0) }) == record.count else {
            throw Failure.socketUnavailable
        }
    }

    private static func recordedOwnership(_ node: Node) -> Data {
        Data("\(node.device):\(node.inode):\(node.createdSeconds):\(node.createdNanoseconds)\n".utf8)
    }

    private static func isNotListening(_ address: Data) -> Bool {
        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else { return false }
        defer { close(descriptor) }
        guard configure(descriptor) else { return false }
        return address.withUnsafeBytes { buffer in
            connect(descriptor, buffer.baseAddress?.assumingMemoryBound(to: sockaddr.self), socklen_t(buffer.count)) == -1
                && errno == ECONNREFUSED
        }
    }

    static func address(_ path: String) throws -> Data {
        let bytes = Array(path.utf8)
        let addressSize = bytes.count + 3
        guard bytes.first == UInt8(ascii: "/"), !bytes.contains(0), bytes.count < MemoryLayout.size(ofValue: sockaddr_un().sun_path) else {
            throw Failure.invalidPath
        }
        return Data([UInt8(addressSize), UInt8(AF_UNIX)] + bytes + [0])
    }
}
