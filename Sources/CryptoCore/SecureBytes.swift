import Foundation

/// A heap buffer of sensitive bytes that is best-effort zeroized on deinit.
/// NOTE: Swift `Array` may copy-on-write; callers must avoid leaking copies.
/// Long-lived keys (e.g. the UserKey in KeyVault) use this type.
public final class SecureBytes: @unchecked Sendable {
    private var storage: [UInt8]

    public init(_ bytes: [UInt8]) { storage = bytes }
    public init(count: Int) { storage = [UInt8](repeating: 0, count: count) }

    public var count: Int { storage.count }
    public var bytes: [UInt8] { storage }
    public var data: Data { Data(storage) }

    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try storage.withUnsafeBytes(body)
    }

    deinit {
        storage.withUnsafeMutableBytes { ptr in
            guard let base = ptr.baseAddress, ptr.count > 0 else { return }
            memset_s(base, ptr.count, 0, ptr.count)
        }
    }
}
