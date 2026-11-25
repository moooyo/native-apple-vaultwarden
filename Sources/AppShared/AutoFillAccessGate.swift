import Darwin
import Foundation

/// An exclusive file lock held by the main app only while the vault is unlocked.
/// The OS releases it on process death. The file contains only a random session ID;
/// it is not deleted, so readers and writers always coordinate on the same inode.
public final class AutoFillAccessGate: @unchecked Sendable {
    private let url: URL
    private let lock = NSLock()
    private var descriptor: Int32 = -1

    public init(url: URL) { self.url = url }

    @discardableResult
    package func activate(sessionID: String) -> Bool {
        guard UUID(uuidString: sessionID) != nil, sessionID.utf8.count == 36 else { return false }
        return lock.withLock {
            release()
            let fd = Darwin.open(url.path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, S_IRUSR | S_IWUSR)
            guard fd >= 0 else { return false }
            guard Self.isOwnerFile(fd), flock(fd, LOCK_EX | LOCK_NB) == 0 else { Darwin.close(fd); return false }
            let bytes = Data(sessionID.utf8)
            let written = bytes.withUnsafeBytes { pwrite(fd, $0.baseAddress, $0.count, 0) }
            guard written == bytes.count, ftruncate(fd, off_t(bytes.count)) == 0 else {
                Darwin.close(fd)
                return false
            }
            descriptor = fd
            return true
        }
    }

    package func deactivate() { lock.withLock { release() } }

    /// A readable session ID is insufficient by itself. Fail closed if the main app
    /// is not holding the lock, or if a stale generation owns it.
    package func permits(sessionID: String) -> Bool {
        guard UUID(uuidString: sessionID) != nil, sessionID.utf8.count == 36 else { return false }
        let fd = Darwin.open(url.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
        guard fd >= 0 else { return false }
        defer { Darwin.close(fd) }
        guard Self.isOwnerFile(fd) else { return false }
        func ownerIsActive() -> Bool {
            if flock(fd, LOCK_SH | LOCK_NB) == 0 { return false }
            return errno == EWOULDBLOCK
        }
        guard ownerIsActive() else { return false }
        var bytes = [UInt8](repeating: 0, count: 37)
        let count = bytes.withUnsafeMutableBytes { pread(fd, $0.baseAddress, $0.count, 0) }
        return count == 36 && bytes.prefix(36).elementsEqual(sessionID.utf8) && ownerIsActive()
    }

    private static func isOwnerFile(_ fd: Int32) -> Bool {
        var info = stat()
        return fstat(fd, &info) == 0 && info.st_mode & S_IFMT == S_IFREG &&
            info.st_uid == geteuid() && info.st_nlink == 1 && info.st_mode & 0o077 == 0
    }

    private func release() {
        if descriptor >= 0 {
            Darwin.close(descriptor)
            descriptor = -1
        }
    }

    deinit { release() }
}
