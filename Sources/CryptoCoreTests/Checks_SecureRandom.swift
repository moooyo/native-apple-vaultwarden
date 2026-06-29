import Foundation
@testable import CryptoCore

func checkSecureRandom(_ r: inout TestRunner) {
    // test_lengthAndUniqueness
    do {
        let a = try SecureRandom.bytes(16)
        let b = try SecureRandom.bytes(16)
        r.expect(a.count, 16, "SecureRandom.bytes(16) length a")
        r.expect(b.count, 16, "SecureRandom.bytes(16) length b")
        r.expectTrue(a != b, "SecureRandom.bytes(16) two draws differ")  // astronomically unlikely to match
    } catch {
        r.expectTrue(false, "SecureRandom.bytes(16) threw: \(error)")
    }

    // test_zeroLength
    do {
        r.expect(try SecureRandom.bytes(0), Data(), "SecureRandom.bytes(0) is empty")
    } catch {
        r.expectTrue(false, "SecureRandom.bytes(0) threw: \(error)")
    }
}
