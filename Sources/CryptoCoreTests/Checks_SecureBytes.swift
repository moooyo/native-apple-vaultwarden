import Foundation
@testable import CryptoCore

func checkSecureBytes(_ r: inout TestRunner) {
    // test_storesAndReturnsBytes — read bytes for assertions via a test-only copy.
    let sb = SecureBytes([1, 2, 3, 4])
    r.expect(sb.count, 4, "SecureBytes count")
    r.expect(sb.withUnsafeBytes { Array($0) }, [1, 2, 3, 4], "SecureBytes bytes")
    r.expect(sb.withUnsafeBytes { Data($0) }, Data([1, 2, 3, 4]), "SecureBytes data")

    // test_zeroInit
    let zeroed = SecureBytes(count: 8)
    r.expect(zeroed.withUnsafeBytes { Array($0) }, [UInt8](repeating: 0, count: 8), "SecureBytes(count:) zero-fills")

    // test_withUnsafeBytes
    let sb2 = SecureBytes([0xAA, 0xBB])
    let first = sb2.withUnsafeBytes { $0.first }
    r.expect(first, 0xAA, "SecureBytes.withUnsafeBytes first byte")

    // test_withUnsafeMutableBytes — in-place population without copying through an Array/Data.
    let sb3 = SecureBytes(count: 4)
    sb3.withUnsafeMutableBytes { ptr in
        for i in 0..<ptr.count { ptr[i] = UInt8(0xF0 + i) }
    }
    r.expect(sb3.withUnsafeBytes { Array($0) }, [0xF0, 0xF1, 0xF2, 0xF3], "SecureBytes.withUnsafeMutableBytes populates in place")
}
