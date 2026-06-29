import Foundation
import VaultModels

func checkEnums(_ r: inout TestRunner) {
    let decoder = VaultJSON.decoder()

    func decode<T: Decodable>(_ type: T.Type, _ value: Int) throws -> T {
        try decoder.decode(T.self, from: "\(value)".data(using: .utf8)!)
    }

    // CipherType
    r.expect(CipherType(rawValue: 1), .login, "CipherType raw 1 == login")
    do {
        r.expect(try decode(CipherType.self, 1), .login, "CipherType decodes 1 -> login")
        r.expect(try decode(CipherType.self, 5), .sshKey, "CipherType decodes 5 -> sshKey")
        r.expect(try decode(CipherType.self, 99), .unknown(99), "CipherType decodes 99 -> unknown(99)")
    } catch { r.expectTrue(false, "CipherType decode threw: \(error)") }

    // SecureNoteType
    do {
        r.expect(try decode(SecureNoteType.self, 0), .generic, "SecureNoteType decodes 0 -> generic")
        r.expect(try decode(SecureNoteType.self, 7), .unknown(7), "SecureNoteType decodes 7 -> unknown(7)")
    } catch { r.expectTrue(false, "SecureNoteType decode threw: \(error)") }

    // FieldType
    do {
        r.expect(try decode(FieldType.self, 0), .text, "FieldType decodes 0 -> text")
        r.expect(try decode(FieldType.self, 1), .hidden, "FieldType decodes 1 -> hidden")
        r.expect(try decode(FieldType.self, 2), .boolean, "FieldType decodes 2 -> boolean")
        r.expect(try decode(FieldType.self, 3), .linked, "FieldType decodes 3 -> linked")
        r.expect(try decode(FieldType.self, 42), .unknown(42), "FieldType decodes 42 -> unknown(42)")
    } catch { r.expectTrue(false, "FieldType decode threw: \(error)") }

    // UriMatchType
    do {
        r.expect(try decode(UriMatchType.self, 0), .domain, "UriMatchType decodes 0 -> domain")
        r.expect(try decode(UriMatchType.self, 5), .never, "UriMatchType decodes 5 -> never")
        r.expect(try decode(UriMatchType.self, 6), .unknown(6), "UriMatchType decodes 6 -> unknown(6)")
    } catch { r.expectTrue(false, "UriMatchType decode threw: \(error)") }

    // SendType
    do {
        r.expect(try decode(SendType.self, 0), .text, "SendType decodes 0 -> text")
        r.expect(try decode(SendType.self, 1), .file, "SendType decodes 1 -> file")
        r.expect(try decode(SendType.self, 9), .unknown(9), "SendType decodes 9 -> unknown(9)")
    } catch { r.expectTrue(false, "SendType decode threw: \(error)") }

    // LinkedIdType (Int wrapper)
    do {
        r.expect(try decode(LinkedIdType.self, 100), LinkedIdType(rawValue: 100), "LinkedIdType decodes 100")
        r.expect(try decode(LinkedIdType.self, 0), LinkedIdType(rawValue: 0), "LinkedIdType decodes 0")
    } catch { r.expectTrue(false, "LinkedIdType decode threw: \(error)") }

    // Round-trip encode/decode (unknown preserved)
    do {
        let data = try VaultJSON.encoder().encode(CipherType.unknown(99))
        r.expect(try decoder.decode(CipherType.self, from: data), .unknown(99), "CipherType unknown round-trips")
    } catch { r.expectTrue(false, "CipherType round-trip threw: \(error)") }
}
