import Foundation

/// An owned allocation that can be wiped in place without triggering copy-on-write.
/// The byte views are valid only during the closure; callers must not reenter the buffer.
public final class SecureBytes: @unchecked Sendable {
    private let lock = NSLock()
    private let storage: UnsafeMutableRawPointer
    public let count: Int

    public convenience init(_ bytes: [UInt8]) {
        self.init(count: bytes.count)
        bytes.withUnsafeBytes { source in
            withUnsafeMutableBytes { $0.copyMemory(from: source) }
        }
    }

    public init(count: Int) {
        precondition(count >= 0)
        self.count = count
        storage = .allocate(byteCount: max(1, count), alignment: MemoryLayout<UInt64>.alignment)
        storage.initializeMemory(as: UInt8.self, repeating: 0, count: count)
    }

    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try lock.withLock { try body(UnsafeRawBufferPointer(start: storage, count: count)) }
    }

    public func withUnsafeMutableBytes<R>(_ body: (UnsafeMutableRawBufferPointer) throws -> R) rethrows -> R {
        try lock.withLock { try body(UnsafeMutableRawBufferPointer(start: storage, count: count)) }
    }

    public func clear() {
        lock.withLock { Self.erase(UnsafeMutableRawBufferPointer(start: storage, count: count)) }
    }

    package static func erase(_ bytes: UnsafeMutableRawBufferPointer) {
        guard let base = bytes.baseAddress, !bytes.isEmpty else { return }
        memset_s(base, bytes.count, 0, bytes.count)
    }

    deinit {
        clear()
        storage.deallocate()
    }
}
