import Darwin
import Foundation

/// All cooperating processes lock the same inode. Never unlink the lock, even when the queue
/// is empty: otherwise two processes could hold exclusive locks on different inodes.
struct HandoffQueueFiles: Sendable {
    private static let maximumMarkerBytes = 256
    private static let lockName = ".queue-lock"

    private let url: URL
    private let directory: Int32
    private let lock: Int32

    static func open(_ url: URL, create: Bool) async throws -> Self? {
        if create, Darwin.mkdir(url.path, 0o700) != 0, errno != EEXIST {
            throw PasskeyHandoffError.storageUnavailable
        }
        let directory = Darwin.open(url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directory >= 0 else {
            if !create, errno == ENOENT { return nil }
            throw PasskeyHandoffError.storageUnavailable
        }
        var directoryInfo = stat()
        guard fstat(directory, &directoryInfo) == 0, directoryInfo.st_uid == geteuid() else {
            Darwin.close(directory)
            throw PasskeyHandoffError.storageUnavailable
        }
        let lock = openat(directory, lockName, O_RDWR | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0o600)
        var lockInfo = stat()
        guard lock >= 0, fstat(lock, &lockInfo) == 0, isOwnedRegularFile(lockInfo),
              fchmod(lock, 0o600) == 0 else {
            if lock >= 0 { Darwin.close(lock) }
            Darwin.close(directory)
            throw PasskeyHandoffError.storageUnavailable
        }
        do {
            // Wait briefly for the other process, without blocking a cooperative executor.
            for _ in 0..<40 {
                if flock(lock, LOCK_EX | LOCK_NB) == 0 {
                    return Self(url: url, directory: directory, lock: lock)
                }
                guard errno == EWOULDBLOCK else { break }
                try await Task.sleep(for: .milliseconds(25))
            }
            throw PasskeyHandoffError.storageUnavailable
        } catch {
            Darwin.close(lock)
            Darwin.close(directory)
            throw error
        }
    }

    func close() {
        Darwin.close(lock)
        Darwin.close(directory)
    }

    func names() throws -> [String] {
        // Enumeration alone never reads a marker. Every subsequent read, rename, or removal
        // is anchored to the opened directory and uses a validated, single-component name.
        do { return try FileManager.default.contentsOfDirectory(atPath: url.path) }
        catch { throw PasskeyHandoffError.storageUnavailable }
    }

    func exists(_ name: String) throws -> Bool {
        var info = stat()
        if fstatat(directory, name, &info, AT_SYMLINK_NOFOLLOW) == 0 { return true }
        if errno == ENOENT { return false }
        throw PasskeyHandoffError.storageUnavailable
    }

    func read(_ name: String) throws -> Data? {
        let descriptor = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard descriptor >= 0 else {
            if errno == ENOENT { return nil }
            throw PasskeyHandoffError.storageUnavailable
        }
        defer { Darwin.close(descriptor) }
        var info = stat()
        guard fstat(descriptor, &info) == 0, Self.isOwnedRegularFile(info),
              info.st_size <= Self.maximumMarkerBytes else {
            throw PasskeyHandoffError.storageUnavailable
        }
        var data = Data(count: Self.maximumMarkerBytes + 1)
        let count = data.withUnsafeMutableBytes { Darwin.read(descriptor, $0.baseAddress, $0.count) }
        guard count >= 0, count == info.st_size else {
            throw PasskeyHandoffError.storageUnavailable
        }
        data.removeSubrange(count..<data.count)
        return data
    }

    func writeMarker(_ marker: Data, named name: String) throws {
        try requireLiveDirectory()
        let options: Data.WritingOptions
        #if os(iOS)
        options = [.atomic, .completeFileProtection]
        #else
        options = [.atomic]
        #endif
        do { try marker.write(to: url.appendingPathComponent(name), options: options) }
        catch { throw PasskeyHandoffError.storageUnavailable }
        let fd = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw PasskeyHandoffError.storageUnavailable }
        defer { Darwin.close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, Self.isOwnedRegularFile(info), fchmod(fd, 0o600) == 0,
              try read(name) == marker else { throw PasskeyHandoffError.storageUnavailable }
    }

    func promote(_ staging: String, to ready: String) throws {
        try requireLiveDirectory()
        guard renameatx_np(directory, staging, directory, ready, UInt32(RENAME_EXCL)) == 0 else {
            throw PasskeyHandoffError.storageUnavailable
        }
    }

    private func requireLiveDirectory() throws {
        var opened = stat()
        var current = stat()
        guard fstat(directory, &opened) == 0, lstat(url.path, &current) == 0,
              opened.st_dev == current.st_dev, opened.st_ino == current.st_ino else {
            throw PasskeyHandoffError.storageUnavailable
        }
    }

    func remove(_ name: String) throws {
        guard unlinkat(directory, name, 0) == 0 || errno == ENOENT else {
            throw PasskeyHandoffError.storageUnavailable
        }
    }

    private static func isOwnedRegularFile(_ info: stat) -> Bool {
        info.st_mode & S_IFMT == S_IFREG && info.st_nlink == 1 && info.st_uid == geteuid()
    }
}
