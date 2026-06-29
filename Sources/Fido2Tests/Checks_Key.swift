import Foundation
import CryptoKit
@testable import Fido2

func checkCredentialKey(_ r: inout TestRunner) {
    let key = CredentialKey()

    // publicKeyX963 is 65 bytes starting with 0x04 (uncompressed point).
    let point = key.publicKeyX963
    r.expect(point.count, 65, "CredentialKey publicKeyX963 is 65 bytes")
    r.expectTrue(point.first == 0x04, "CredentialKey publicKeyX963 starts with 0x04")

    // PKCS8 export/import round-trips: same public point.
    let der = key.exportPKCS8()
    do {
        let imported = try CredentialKey(pkcs8: der)
        r.expect(imported.publicKeyX963, point, "CredentialKey PKCS8 round-trip preserves public point")
    } catch {
        r.expectTrue(false, "CredentialKey PKCS8 round-trip threw: \(error)")
    }

    // Invalid PKCS8 DER throws Fido2Error.invalidKey.
    r.expectThrowsError(Fido2Error.invalidKey, "CredentialKey(pkcs8:) invalid -> invalidKey") {
        _ = try CredentialKey(pkcs8: Data([0x00, 0x01, 0x02]))
    }

    // Format lock: exportPKCS8() must genuinely be PKCS#8 PrivateKeyInfo, NOT SEC1.
    // Robust to a +/-1 length-byte variation (we do NOT assert the total length byte).
    //  - version INTEGER 0 = bytes 02 01 00 present near the start.
    //  - AlgorithmIdentifier = id-ecPublicKey OID (06 07 2A 86 48 CE 3D 02 01)
    //    followed by prime256v1 OID (06 08 2A 86 48 CE 3D 03 01 07), contiguous.
    // A SEC1 EC private key (RFC 5915) would instead start 30 .. 02 01 01 04 20 .. and
    // would not contain the id-ecPublicKey OID span at all.
    let pkcs8 = key.exportPKCS8()
    r.expectTrue(pkcs8.prefix(8).contains([0x02, 0x01, 0x00]),
                 "exportPKCS8 contains version INTEGER 0 (02 01 00) near start")
    let ecOIDspan: [UInt8] = [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
                              0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]
    r.expectTrue(pkcs8.contains(ecOIDspan),
                 "exportPKCS8 contains id-ecPublicKey + prime256v1 OID span (PKCS#8, not SEC1)")
}

func checkCOSEKey(_ r: inout TestRunner) {
    let key = CredentialKey()
    let point = key.publicKeyX963
    let cose: Data
    do {
        cose = try COSEKey.encode(publicKeyX963: point)
    } catch {
        r.expectTrue(false, "COSEKey.encode threw on valid point: \(error)")
        return
    }

    // 5-entry map => first byte 0xa5.
    r.expect(cose.first, 0xa5, "COSEKey map starts with 0xa5 (5 entries)")

    // Build the expected map bytes ourselves and compare exactly.
    let x = point.subdata(in: 1..<33)
    let y = point.subdata(in: 33..<65)
    let expected = CBOR.map([
        (.int(1), .int(2)),    // kty: EC2
        (.int(3), .int(-7)),   // alg: ES256
        (.int(-1), .int(1)),   // crv: P-256
        (.int(-2), .bytes(x)),
        (.int(-3), .bytes(y)),
    ]).encoded()
    r.expect(cose, expected, "COSEKey encodes EC2/ES256/P-256 map exactly")

    // Spot-check label/value bytes inside the encoding.
    // kty label 0x01 -> value 0x02
    r.expectTrue(cose.contains([0x01, 0x02]), "COSEKey contains kty 1:2")
    // alg label 0x03 -> value 0x26 (negint -7)
    r.expectTrue(cose.contains([0x03, 0x26]), "COSEKey contains alg 3:-7")
    // crv label 0x20 (negint -1) -> value 0x01
    r.expectTrue(cose.contains([0x20, 0x01]), "COSEKey contains crv -1:1")
    // X label 0x21 (negint -2) -> 0x58 0x20 (byte string of length 32) then X
    r.expectTrue(cose.contains([0x21, 0x58, 0x20] + Array(x)), "COSEKey contains -2:<32B X>")
    // Y label 0x22 (negint -3) -> 0x58 0x20 then Y
    r.expectTrue(cose.contains([0x22, 0x58, 0x20] + Array(y)), "COSEKey contains -3:<32B Y>")

    // Bad input throws instead of trapping.
    r.expectThrowsError(Fido2Error.invalidKey, "COSEKey.encode short point -> invalidKey") {
        _ = try COSEKey.encode(publicKeyX963: Data([0x04, 0x01, 0x02]))
    }
    r.expectThrowsError(Fido2Error.invalidKey, "COSEKey.encode wrong prefix -> invalidKey") {
        _ = try COSEKey.encode(publicKeyX963: Data([0x00] + Array(repeating: 0, count: 64)))
    }
}

// Small helper: does Data contain the given byte subsequence?
private extension Data {
    func contains(_ sub: [UInt8]) -> Bool {
        guard !sub.isEmpty, count >= sub.count else { return false }
        let bytes = Array(self)
        for start in 0...(bytes.count - sub.count) {
            if Array(bytes[start..<(start + sub.count)]) == sub { return true }
        }
        return false
    }
}
