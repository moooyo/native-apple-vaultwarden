import Foundation

/// Minimal test harness (XCTest is unavailable on this CLT-only host).
/// Mirrors the harness used by the other package test targets.
struct TestRunner {
    private(set) var passed = 0
    private(set) var failed = 0

    mutating func expect<T: Equatable>(_ actual: T, _ expected: T, _ name: String) {
        if actual == expected { passed += 1 }
        else { failed += 1; print("FAIL  \(name)\n   got: \(String(describing: actual))\n   exp: \(String(describing: expected))") }
    }

    mutating func expectTrue(_ condition: Bool, _ name: String) {
        if condition { passed += 1 } else { failed += 1; print("FAIL  \(name): expected true") }
    }

    /// Compare two Doubles within a small tolerance.
    mutating func expectClose(_ actual: Double, _ expected: Double, _ name: String, tol: Double = 1e-9) {
        if abs(actual - expected) <= tol { passed += 1 }
        else { failed += 1; print("FAIL  \(name)\n   got: \(actual)\n   exp: \(expected)") }
    }

    func summary() -> Int {
        print("— \(passed) passed, \(failed) failed —")
        return failed
    }
}
