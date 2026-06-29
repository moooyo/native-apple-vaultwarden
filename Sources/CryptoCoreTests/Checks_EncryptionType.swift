import Foundation
@testable import CryptoCore

func checkEncryptionType(_ r: inout TestRunner) {
    // test_rawValues
    r.expect(EncryptionType.aesCbc256_HmacSha256_B64.rawValue, 2, "EncryptionType.aesCbc256_HmacSha256_B64 raw == 2")
    r.expect(EncryptionType.rsa2048_OaepSha1_B64.rawValue, 4, "EncryptionType.rsa2048_OaepSha1_B64 raw == 4")
    r.expect(EncryptionType.coseEncrypt0_B64.rawValue, 7, "EncryptionType.coseEncrypt0_B64 raw == 7")
    r.expectTrue(EncryptionType(rawValue: 99) == nil, "EncryptionType(rawValue: 99) is nil")

    // test_hexHelper
    r.expect(Data([0x00, 0xff, 0x10]).hexString, "00ff10", "Data.hexString encodes bytes")
    r.expect(Data(hex: "00ff10"), Data([0x00, 0xff, 0x10]), "Data(hex:) decodes hex")
}
