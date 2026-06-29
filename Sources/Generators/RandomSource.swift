import Foundation
import CryptoCore

/// A source of uniform random integers, injectable so generators are deterministic
/// in tests (via a mock) and CSPRNG-backed in production.
public protocol RandomSource: Sendable {
    /// Uniform random `Int` in `0..<upperBound` (`upperBound` must be > 0).
    func int(upperBound: Int) -> Int
}

/// Production `RandomSource` backed by `CryptoCore.SecureRandom`.
///
/// Uses rejection sampling over a full 64-bit draw to avoid modulo bias.
public struct SystemRandomSource: RandomSource {
    public init() {}

    public func int(upperBound: Int) -> Int {
        precondition(upperBound > 0, "upperBound must be positive")
        if upperBound == 1 { return 0 }
        // Reject the unevenly-distributed tail so every value in 0..<upperBound is equally likely.
        let range = UInt64(upperBound)
        let maxUnbiased = UInt64.max - (UInt64.max % range)
        while true {
            let r = randomU64()
            if r < maxUnbiased { return Int(r % range) }
        }
    }

    private func randomU64() -> UInt64 {
        let data = (try? SecureRandom.bytes(8)) ?? Data((0..<8).map { _ in UInt8.random(in: .min ... .max) })
        return data.withUnsafeBytes { $0.loadUnaligned(as: UInt64.self) }
    }
}
