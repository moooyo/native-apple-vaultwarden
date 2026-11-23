import Darwin
import Foundation
import os

struct MacSSHAgentPeer: Equatable, Sendable {
    enum Scope: Hashable, Sendable {
        case process([UInt32], executable: String)
        case connection(UUID)
    }

    let scope: Scope
    let pid: pid_t?
    let name: String?

    fileprivate init(fileDescriptor: Int32) {
        var token = audit_token_t()
        var size = socklen_t(MemoryLayout.size(ofValue: token))
        guard getsockopt(fileDescriptor, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &size) == 0,
              size == MemoryLayout.size(ofValue: token), token.val.5 > 0, token.val.7 > 0 else {
            scope = .connection(UUID())
            pid = nil
            name = nil
            return
        }
        pid = pid_t(bitPattern: token.val.5)
        var buffer = [UInt8](repeating: 0, count: 4 * Int(MAXPATHLEN))
        let written = buffer.withUnsafeMutableBytes { bytes in
            proc_pidpath_audittoken(&token, bytes.baseAddress, UInt32(bytes.count))
        }
        guard written > 0, written <= buffer.count,
              let executable = String(bytes: buffer.prefix(Int(written)).prefix(while: { $0 != 0 }), encoding: .utf8),
              executable.hasPrefix("/") else {
            scope = .connection(UUID())
            name = nil
            return
        }
        let words = withUnsafeBytes(of: token) { Array($0.bindMemory(to: UInt32.self)) }
        scope = .process(words, executable: executable)
        name = MacSSHAgentProtocol.safeLabel((executable as NSString).lastPathComponent)
    }

    init(scope: Scope, pid: pid_t? = nil, name: String? = nil) {
        self.scope = scope
        self.pid = pid
        self.name = name
    }
}

struct MacSSHAgentSocketReply: Sendable {
    let packet: Data
    var closesConnection = false
    var validatesOnSend: (@Sendable () async -> Bool)?
    var didSend: (@Sendable () async -> Void)?

    static let failure = Self(packet: MacSSHAgentProtocol.failure)
}

final class MacSSHAgentSocket: Sendable {
    enum Failure: Error, Equatable {
        case invalidPath
        case unsafeDirectory
        case occupied
        case socketUnavailable
    }

    typealias Handler = @Sendable (MacSSHAgentProtocol.Request, MacSSHAgentPeer) async -> MacSSHAgentSocketReply

    let path: String
    private let fileDescriptor: Int32
    private let source: any DispatchSourceRead
    private let state = OSAllocatedUnfairLock(initialState: State())
    private let node: Node
    private let ownership: Int32
    private let handler: Handler

    private static let maximumConnections = 8
    private static let maximumPacketsPerConnection = 96
    private static let ioTimeout: Duration = .seconds(3)
    private static let idleTimeout: Duration = .seconds(30)

    private struct State: Sendable {
        var stopped = false
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

        static func current(at path: String) -> Node? {
            var info = stat()
            guard lstat(path, &info) == 0,
                  (info.st_mode & S_IFMT) == S_IFSOCK, info.st_uid == geteuid() else { return nil }
            return Node(info)
        }
    }

    static func defaultPath() -> String {
        (NSHomeDirectory() as NSString).appendingPathComponent(".openvault/ssh")
    }

    init(path: String, handler: @escaping Handler) throws {
        self.path = path
        self.handler = handler
        let address = try Self.address(path)
        let directory = (path as NSString).deletingLastPathComponent
        try Self.prepareDirectory(directory)
        let ownership = try Self.lockOwnership(in: directory)
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
        fileDescriptor = listener
        node = created
        self.ownership = ownership
        source = DispatchSource.makeReadSource(fileDescriptor: listener, queue: DispatchQueue(label: "org.openvault.ssh-listener"))
        source.setCancelHandler { close(listener) }
        source.setEventHandler { [weak self] in self?.acceptConnections() }
        ownsPath = true
        listening = true
        source.resume()
    }

    deinit { stop() }

    func stop() {
        let tasks = state.withLock { values -> [Task<Void, Never>]? in
            guard !values.stopped else { return nil }
            values.stopped = true
            for descriptor in values.connections.keys { shutdown(descriptor, SHUT_RDWR) }
            return Array(values.connections.values)
        }
        guard let tasks else { return }
        for task in tasks { task.cancel() }
        if Node.current(at: path) == node, unlink(path) == 0 { _ = ftruncate(ownership, 0) }
        close(ownership)
        source.cancel()
    }

    private func acceptConnections() {
        for _ in 0..<Self.maximumConnections {
            let accepted = state.withLock { values in
                guard !values.stopped else { return false }
                let client = accept(fileDescriptor, nil, nil)
                guard client >= 0 else { return errno == EINTR }
                guard values.connections.count < Self.maximumConnections, Self.accepts(client), Self.configure(client) else {
                    close(client)
                    return true
                }
                let peer = MacSSHAgentPeer(fileDescriptor: client)
                values.connections[client] = Task.detached { [weak self, handler] in
                    defer { if let self { self.finish(client) } else { close(client) } }
                    await Self.handle(client, peer: peer, handler: handler)
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

    private static func handle(_ descriptor: Int32, peer: MacSSHAgentPeer, handler: Handler) async {
        for _ in 0..<maximumPacketsPerConnection {
            let clock = ContinuousClock()
            guard let first = await read(1, from: descriptor, until: clock.now.advanced(by: idleTimeout)) else { return }
            let deadline = clock.now.advanced(by: ioTimeout)
            guard let rest = await read(3, from: descriptor, until: deadline) else { return }
            let count = (first + rest).reduce(0) { ($0 << 8) | Int($1) }
            guard (1...MacSSHAgentProtocol.maximumPacketSize).contains(count),
                  let packet = await read(count, from: descriptor, until: deadline) else { return }
            let request = MacSSHAgentProtocol.request(packet)
            let reply = await handler(request, peer)
            guard !Task.isCancelled else { return }
            let permitted = await reply.validatesOnSend?() ?? true
            guard !Task.isCancelled else { return }
            let response = permitted ? reply.packet : MacSSHAgentProtocol.failure
            let framed = MacSSHAgentProtocol.uint32(UInt32(response.count)) + response
            if response.first == 14 {
                let written = framed.withUnsafeBytes { send(descriptor, $0.baseAddress, $0.count, 0) }
                guard written == framed.count else { return }
                await reply.didSend?()
            } else {
                guard await write(framed, to: descriptor, until: clock.now.advanced(by: ioTimeout)) else { return }
            }
            if reply.closesConnection { return }
        }
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

    private static func lockOwnership(in directory: String) throws -> Int32 {
        let path = (directory as NSString).appendingPathComponent(".ssh-owner")
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
