import Foundation
@testable import Generators

func checkBase32(_ r: inout TestRunner) {
    // "JBSWY3DPEHPK3PXP" decodes to "Hello!" + 0xDE 0xAD 0xBE 0xEF
    let expectedHello = Data([0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0xde, 0xad, 0xbe, 0xef]) // "Hello!" + deadbeef
    r.expect(Base32.decode("JBSWY3DPEHPK3PXP"), expectedHello, "Base32.decode(JBSWY3DPEHPK3PXP) == Hello!deadbeef")

    // Lowercase input works (case-insensitive)
    r.expect(Base32.decode("jbswy3dpehpk3pxp"), expectedHello, "Base32.decode lowercase")

    // Spaces tolerated
    r.expect(Base32.decode("JBSW Y3DP EHPK 3PXP"), expectedHello, "Base32.decode with spaces")

    // Padding '=' tolerated
    r.expect(Base32.decode("JBSWY3DPEHPK3PXP="), expectedHello, "Base32.decode with padding")

    // Known RFC pair: GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ -> ASCII "12345678901234567890"
    let expectedSeed = "12345678901234567890".data(using: .ascii)!
    r.expect(Base32.decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"), expectedSeed, "Base32.decode RFC seed == 12345678901234567890")

    // Invalid characters -> nil
    r.expect(Base32.decode("0189!@#$"), nil, "Base32.decode invalid chars -> nil")
}
