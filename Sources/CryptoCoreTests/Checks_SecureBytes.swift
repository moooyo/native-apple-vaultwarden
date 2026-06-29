import Foundation
@testable import CryptoCore

func checkSecureBytes(_ r: inout TestRunner) {
    // test_storesAndReturnsBytes
    let sb = SecureBytes([1, 2, 3, 4])
    r.expect(sb.count, 4, "SecureBytes count")
    r.expect(sb.bytes, [1, 2, 3, 4], "SecureBytes bytes")
    r.expect(sb.data, Data([1, 2, 3, 4]), "SecureBytes data")

    // test_zeroInit
    let zeroed = SecureBytes(count: 8)
    r.expect(zeroed.bytes, [UInt8](repeating: 0, count: 8), "SecureBytes(count:) zero-fills")

    // test_withUnsafeBytes
    let sb2 = SecureBytes([0xAA, 0xBB])
    let first = sb2.withUnsafeBytes { $0.first }
    r.expect(first, 0xAA, "SecureBytes.withUnsafeBytes first byte")
}
