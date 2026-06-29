import Foundation
@testable import CryptoCore

func checkEncStringCodable(_ r: inout TestRunner) {
    // A struct field of type EncString decoded from a JSON string value.
    struct Wrapper: Codable, Equatable { let key: EncString }

    let iv = Data((0..<16).map { UInt8($0) })
    let ct = Data((16..<32).map { UInt8($0) })
    let mac = Data((32..<64).map { UInt8($0) })
    let enc = EncString(type: .aesCbc256_HmacSha256_B64, iv: iv, ciphertext: ct, mac: mac)
    let wire = enc.stringValue

    // test_decodeFromJSONStringValue
    do {
        let json = "{\"key\":\"\(wire)\"}".data(using: .utf8)!
        let decoded = try JSONDecoder().decode(Wrapper.self, from: json)
        r.expect(decoded.key, enc, "EncString decodes from JSON string value")
    } catch {
        r.expectTrue(false, "EncString JSON decode threw: \(error)")
    }

    // test_roundTripEncodeDecode
    do {
        let original = Wrapper(key: enc)
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(Wrapper.self, from: data)
        r.expect(decoded, original, "EncString Codable round-trips")
    } catch {
        r.expectTrue(false, "EncString round-trip threw: \(error)")
    }

    // test_encodesToWireString
    do {
        let data = try JSONEncoder().encode(Wrapper(key: enc))
        let s = String(data: data, encoding: .utf8)!
        r.expectTrue(s.contains(wire), "EncString encodes to its wire stringValue")
    } catch {
        r.expectTrue(false, "EncString encode threw: \(error)")
    }

    // test_invalidStringThrows
    r.expectThrows("EncString decode throws on invalid wire string") {
        let json = "{\"key\":\"not-a-valid-encstring\"}".data(using: .utf8)!
        _ = try JSONDecoder().decode(Wrapper.self, from: json)
    }
}
