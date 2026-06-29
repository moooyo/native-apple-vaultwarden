import Generators

/// Deterministic random source for exact-output tests.
/// Yields the scripted sequence in order, wrapping when exhausted; each value is
/// reduced modulo the requested `upperBound` so it is always in range.
final class MockRandomSource: RandomSource, @unchecked Sendable {
    private let seq: [Int]
    private var i = 0
    init(sequence: [Int]) { seq = sequence.isEmpty ? [0] : sequence }
    func int(upperBound: Int) -> Int {
        defer { i += 1 }
        return seq[i % seq.count] % upperBound
    }
}
