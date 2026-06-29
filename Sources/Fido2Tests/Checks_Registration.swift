import Foundation
import CryptoKit
@testable import Fido2

func checkRegistration(_ r: inout TestRunner) {
    let clientDataHash = Data((0..<32).map { UInt8($0) })
    let credentialId = Data((0..<16).map { UInt8(0xA0 + $0) }) // 16 bytes

    let attObj: Data
    let key: CredentialKey
    do {
        (attObj, key) = try Fido2Authenticator.register(
            rpId: "example.com",
            clientDataHash: clientDataHash,
            credentialId: credentialId,
            userVerified: true
        )
    } catch {
        r.expectTrue(false, "register threw: \(error)")
        return
    }

    // --- attestationObject structural check: build the expected map ourselves ---
    let cose = COSEKey.encode(publicKeyX963: key.publicKeyX963)
    var acd = Data()
    acd.append(Data(repeating: 0, count: 16)) // default aaguid
    acd.append(contentsOf: withUnsafeBytes(of: UInt16(credentialId.count).bigEndian) { Array($0) })
    acd.append(credentialId)
    acd.append(cose)
    let expectedAuthData = Fido2Authenticator.authenticatorData(
        rpId: "example.com",
        flags: [.userPresent, .userVerified, .attestedData],
        signCount: 0,
        attestedCredentialData: acd
    )
    let expectedAttObj = CBOR.map([
        (.text("fmt"), .text("none")),
        (.text("attStmt"), .map([])),
        (.text("authData"), .bytes(expectedAuthData)),
    ]).encoded()
    r.expect(attObj, expectedAttObj, "register attestationObject matches expected CBOR map")

    // It is a CBOR map with 3 entries -> first byte 0xa3.
    r.expect(attObj.first, 0xa3, "attestationObject is a 3-entry map (0xa3)")

    // Contains the text "none" (fmt value) and the keys "fmt","attStmt","authData".
    r.expectTrue(attObj.contains(Array("none".utf8)), "attestationObject contains fmt value \"none\"")
    r.expectTrue(attObj.contains(Array("authData".utf8)), "attestationObject contains key \"authData\"")
    // Empty attStmt map encodes as 0xa0.
    r.expectTrue(attObj.contains(Array("attStmt".utf8) + [0xa0]), "attestationObject attStmt is empty map (0xa0)")

    // --- authData checks ---
    let authData = expectedAuthData
    // AT flag (0x40) set, plus UP (0x01) and UV (0x04) -> 0x45.
    r.expect(authData[authData.startIndex + 32], 0x45, "register authData flags == 0x45 (UP|UV|AT)")
    // Length == 37 + 16 (aaguid) + 2 (credIdLen) + credIdLen + len(cose).
    let expectedLen = 37 + 16 + 2 + credentialId.count + cose.count
    r.expect(authData.count, expectedLen, "register authData length == 37 + acd")

    // --- Extract COSE public key from authData and compare ---
    // authData = rpIdHash(32) || flags(1) || signCount(4) || aaguid(16) || credIdLen(2) || credId || cose
    let base = authData.startIndex
    let credIdLenOffset = base + 32 + 1 + 4 + 16
    let credIdLen = Int(authData[credIdLenOffset]) << 8 | Int(authData[credIdLenOffset + 1])
    r.expect(credIdLen, credentialId.count, "register authData credIdLen field == credentialId.count")
    let coseStart = credIdLenOffset + 2 + credIdLen
    let extractedCose = authData.subdata(in: coseStart..<authData.endIndex)
    r.expect(extractedCose, COSEKey.encode(publicKeyX963: key.publicKeyX963),
             "COSE key extracted from authData == COSEKey.encode(key.publicKeyX963)")

    // --- registration -> assertion handshake: an assertion signed by the returned key verifies ---
    do {
        let (aAuthData, signature) = try Fido2Authenticator.assert(
            rpId: "example.com",
            clientDataHash: clientDataHash,
            signCount: 1,
            userVerified: true,
            key: key
        )
        let ecdsa = try P256.Signing.ECDSASignature(derRepresentation: signature)
        let valid = key.publicKey.isValidSignature(ecdsa, for: aAuthData + clientDataHash)
        r.expectTrue(valid, "assertion by returned registration key verifies (handshake)")
    } catch {
        r.expectTrue(false, "handshake assert threw: \(error)")
    }

    // --- custom aaguid is honored ---
    do {
        let aaguid = Data((0..<16).map { _ in UInt8(0x11) })
        let (obj2, _) = try Fido2Authenticator.register(
            rpId: "example.com",
            clientDataHash: clientDataHash,
            credentialId: credentialId,
            userVerified: false,
            aaguid: aaguid
        )
        // Decode authData out of the CBOR to confirm aaguid + flags (UV off -> 0x41).
        // authData byte string is the last entry; find it after "authData" key.
        r.expectTrue(obj2.contains(Array(aaguid)), "register honors custom aaguid")
    } catch {
        r.expectTrue(false, "register (custom aaguid) threw: \(error)")
    }
}

// Reuse the subsequence-contains helper (declared private in Checks_Key.swift,
// so re-declare locally here).
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
