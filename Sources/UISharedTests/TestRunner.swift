import Foundation

/// Minimal test harness (XCTest is unavailable on this CLT-only host). Mirrors the harness
/// used by the other packages. Keep an instance local to a function so Swift 6 MainActor
/// isolation is satisfied.
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

    mutating func expectFalse(_ condition: Bool, _ name: String) {
        if !condition { passed += 1 } else { failed += 1; print("FAIL  \(name): expected false") }
    }

    mutating func expectNil<T>(_ value: T?, _ name: String) {
        if value == nil { passed += 1 } else { failed += 1; print("FAIL  \(name): expected nil, got \(String(describing: value))") }
    }

    mutating func expectNotNil<T>(_ value: T?, _ name: String) {
        if value != nil { passed += 1 } else { failed += 1; print("FAIL  \(name): expected non-nil") }
    }

    func summary() -> Int {
        print("— \(passed) passed, \(failed) failed —")
        return failed
    }
}
