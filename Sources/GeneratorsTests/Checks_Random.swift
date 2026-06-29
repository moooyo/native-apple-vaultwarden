import Foundation
@testable import Generators

func checkRandom(_ r: inout TestRunner) {
    // MockRandomSource yields its sequence in order (wrapping), reduced mod upperBound.
    let mock = MockRandomSource(sequence: [0, 1, 2])
    r.expect(mock.int(upperBound: 10), 0, "mock yields 0")
    r.expect(mock.int(upperBound: 10), 1, "mock yields 1")
    r.expect(mock.int(upperBound: 10), 2, "mock yields 2")
    r.expect(mock.int(upperBound: 10), 0, "mock wraps to 0")

    // SystemRandomSource: upperBound 1 always returns 0.
    let sys = SystemRandomSource()
    var allZero = true
    for _ in 0..<100 where sys.int(upperBound: 1) != 0 { allZero = false }
    r.expectTrue(allZero, "SystemRandomSource int(upperBound:1) always 0")

    // Over many draws of int(upperBound: 6): all values 0..<6 appear, none out of range.
    var seen = Set<Int>()
    var inRange = true
    for _ in 0..<5000 {
        let v = sys.int(upperBound: 6)
        if v < 0 || v >= 6 { inRange = false }
        seen.insert(v)
    }
    r.expectTrue(inRange, "SystemRandomSource int(upperBound:6) all in range")
    r.expect(seen, Set(0..<6), "SystemRandomSource int(upperBound:6) covers all values")

    // Non-power-of-two bound (10) never returns >= bound.
    var inRange10 = true
    for _ in 0..<5000 where sys.int(upperBound: 10) >= 10 { inRange10 = false }
    r.expectTrue(inRange10, "SystemRandomSource int(upperBound:10) never >= 10")
}
