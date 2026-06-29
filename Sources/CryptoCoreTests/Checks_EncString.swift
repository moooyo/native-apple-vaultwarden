import Foundation
@testable import CryptoCore

func checkEncString(_ r: inout TestRunner) {
    // iv=16 bytes, ct=16 bytes, mac=32 bytes (lengths typical for type 2)
    let iv = Data((0..<16).map { UInt8($0) })
    let ct = Data((16..<32).map { UInt8($0) })
    let mac = Data((32..<64).map { UInt8($0) })

    // test_roundTripType2
    do {
        let original = EncString(type: .aesCbc256_HmacSha256_B64, iv: iv, ciphertext: ct, mac: mac)
        let string = original.stringValue
        r.expectTrue(string.hasPrefix("2."), "EncString type 2 stringValue prefix")
        r.expect(string.split(separator: ".")[1].split(separator: "|").count, 3, "EncString type 2 has 3 pipe parts")

        let parsed = try EncString(parsing: string)
        r.expect(parsed, original, "EncString type 2 round-trips")
    } catch {
        r.expectTrue(false, "EncString type 2 round-trip threw: \(error)")
    }

    // test_parseType4SinglePart
    do {
        let data = Data((0..<256).map { UInt8($0 & 0xff) })
        let s = "4.\(data.base64EncodedString())"
        let parsed = try EncString(parsing: s)
        r.expect(parsed.type, .rsa2048_OaepSha1_B64, "EncString type 4 type")
        r.expectTrue(parsed.iv == nil, "EncString type 4 iv is nil")
        r.expectTrue(parsed.mac == nil, "EncString type 4 mac is nil")
        r.expect(parsed.ciphertext, data, "EncString type 4 ciphertext")
    } catch {
        r.expectTrue(false, "EncString type 4 parse threw: \(error)")
    }

    // test_rejectsMissingDot
    r.expectThrows("EncString rejects missing dot") {
        _ = try EncString(parsing: "2")
    }

    // test_rejectsWrongPartCountForType2
    r.expectThrows("EncString rejects wrong part count for type 2") {
        _ = try EncString(parsing: "2.\(iv.base64EncodedString())|\(ct.base64EncodedString())")
    }

    // test_unsupportedTypeThrows — out-of-range type integer must throw invalidEncString.
    r.expectThrows("EncString rejects out-of-range type integer") {
        _ = try EncString(parsing: "42.\(ct.base64EncodedString())")
    }
}
