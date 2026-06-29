import Foundation

/// A heap buffer of sensitive bytes that is best-effort zeroized on deinit.
///
/// The zeroization contract is preserved by NOT exposing any accessor that copies
/// the key material out (e.g. `var bytes: [UInt8]` or `var data: Data` would
/// duplicate secrets into un-zeroized heap storage, defeating this type's purpose).
/// Callers read and populate the buffer in place via `withUnsafeBytes` /
/// `withUnsafeMutableBytes`, so secrets never round-trip through an Array/Data copy.
/// Long-lived keys (e.g. the UserKey in KeyVault) use this type.
public final class SecureBytes: @unchecked Sendable {
    private var storage: [UInt8]

    public init(_ bytes: [UInt8]) { storage = bytes }
    public init(count: Int) { storage = [UInt8](repeating: 0, count: count) }

    public var count: Int { storage.count }

    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try storage.withUnsafeBytes(body)
    }

    /// In-place mutable access for populating the buffer without copying secrets
    /// through an intermediate Array/Data.
    public func withUnsafeMutableBytes<R>(_ body: (UnsafeMutableRawBufferPointer) throws -> R) rethrows -> R {
        try storage.withUnsafeMutableBytes(body)
    }

    deinit {
        storage.withUnsafeMutableBytes { ptr in
            guard let base = ptr.baseAddress, ptr.count > 0 else { return }
            memset_s(base, ptr.count, 0, ptr.count)
        }
    }
}
