import Foundation
@testable import Fido2

func checkCBOR(_ r: inout TestRunner) {
    // Unsigned integers (RFC 8949 §3.1, major type 0)
    r.expect(CBOR.uint(0).encoded().hexString, "00", "CBOR uint 0")
    r.expect(CBOR.uint(23).encoded().hexString, "17", "CBOR uint 23")
    r.expect(CBOR.uint(24).encoded().hexString, "1818", "CBOR uint 24")
    r.expect(CBOR.uint(255).encoded().hexString, "18ff", "CBOR uint 255")
    r.expect(CBOR.uint(256).encoded().hexString, "190100", "CBOR uint 256")
    r.expect(CBOR.uint(1_000_000).encoded().hexString, "1a000f4240", "CBOR uint 1000000")

    // Negative integers (major type 1); value encoded as (-1 - n).
    r.expect(CBOR.int(-1).encoded().hexString, "20", "CBOR negint -1")
    r.expect(CBOR.int(-7).encoded().hexString, "26", "CBOR negint -7 (ES256 label)")

    // Byte string (major type 2)
    r.expect(CBOR.bytes(Data([0x01, 0x02])).encoded().hexString, "420102", "CBOR bytes 0102")

    // Text string (major type 3)
    r.expect(CBOR.text("a").encoded().hexString, "6161", "CBOR text \"a\"")

    // Array (major type 4)
    r.expect(CBOR.array([.int(1), .int(2)]).encoded().hexString, "820102", "CBOR array [1,2]")

    // Map (major type 5)
    r.expect(CBOR.map([(.int(1), .int(2)), (.int(3), .int(4))]).encoded().hexString,
             "a201020304", "CBOR map {1:2,3:4}")
}
