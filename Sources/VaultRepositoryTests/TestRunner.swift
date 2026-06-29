import Foundation

/// Minimal test harness (XCTest is unavailable on this CLT-only host).
/// Keep an instance local to a function so Swift 6 MainActor isolation is satisfied.
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

    mutating func expectThrowsAsync(_ name: String, _ body: () async throws -> Void) async {
        do { try await body(); failed += 1; print("FAIL  \(name): expected an error") }
        catch { passed += 1 }
    }

    mutating func expectThrowsErrorAsync<E: Error & Equatable>(_ expected: E, _ name: String, _ body: () async throws -> Void) async {
        do { try await body(); failed += 1; print("FAIL  \(name): expected \(expected)") }
        catch let error as E where error == expected { passed += 1 }
        catch { failed += 1; print("FAIL  \(name): wrong error \(error), expected \(expected)") }
    }

    func summary() -> Int {
        print("— \(passed) passed, \(failed) failed —")
        return failed
    }
}
