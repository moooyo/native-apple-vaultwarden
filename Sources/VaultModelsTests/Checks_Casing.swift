import Foundation
import VaultModels

func checkCasing(_ r: inout TestRunner) {
    // Models follow the project-wide contract: CodingKeys raw values are the
    // lowercased form of the wire key, so the lowercasing decode strategy matches.
    struct S: Codable, Equatable {
        let foo: Int
        let barBaz: Int
        enum CodingKeys: String, CodingKey { case foo, barBaz = "barbaz" }
    }

    let decoder = VaultJSON.decoder()

    // test_decodesPascalCaseAndCamelCaseMix_variantA
    do {
        let json = #"{"Foo":1,"barBaz":2}"#.data(using: .utf8)!
        let s = try decoder.decode(S.self, from: json)
        r.expect(s.foo, 1, "casing variant A foo")
        r.expect(s.barBaz, 2, "casing variant A barBaz")
    } catch {
        r.expectTrue(false, "casing variant A threw: \(error)")
    }

    // test_decodesPascalCaseAndCamelCaseMix_variantB
    do {
        let json = #"{"foo":1,"BarBaz":2}"#.data(using: .utf8)!
        let s = try decoder.decode(S.self, from: json)
        r.expect(s.foo, 1, "casing variant B foo")
        r.expect(s.barBaz, 2, "casing variant B barBaz")
    } catch {
        r.expectTrue(false, "casing variant B threw: \(error)")
    }

    // test_dateWithFractionalSeconds
    struct D: Codable { let when: Date }
    do {
        let json = #"{"when":"2026-01-01T00:00:00.500Z"}"#.data(using: .utf8)!
        let d = try decoder.decode(D.self, from: json)
        r.expectTrue(d.when.timeIntervalSince1970 > 0, "date with fractional seconds decodes")
    } catch {
        r.expectTrue(false, "fractional date threw: \(error)")
    }

    // test_dateWithoutFractionalSeconds
    do {
        let json = #"{"when":"2026-01-01T00:00:00Z"}"#.data(using: .utf8)!
        let d = try decoder.decode(D.self, from: json)
        r.expectTrue(d.when.timeIntervalSince1970 > 0, "date without fractional seconds decodes")
    } catch {
        r.expectTrue(false, "plain date threw: \(error)")
    }
}
