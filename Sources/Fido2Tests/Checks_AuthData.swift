import Foundation
import CryptoKit
@testable import Fido2

func checkAuthData(_ r: inout TestRunner) {
    // SHA256("example.com") golden value.
    let rpIdHashGolden = "a379a6f6eeafb9a55e378c118034e2751e682fab9f2d30ab13d2125586ce1947"

    // authenticatorData for rpId "example.com", flags UP|UV (0x05), signCount 0.
    let authData = Fido2Authenticator.authenticatorData(
        rpId: "example.com",
        flags: [.userPresent, .userVerified],
        signCount: 0
    )
    r.expect(authData.count, 37, "authenticatorData (no attested) is 37 bytes")
    r.expect(authData.hexString,
             "a379a6f6eeafb9a55e378c118034e2751e682fab9f2d30ab13d2125586ce19470500000000",
             "authenticatorData example.com / UP|UV / signCount 0 matches golden")

    // First 32 bytes == SHA256("example.com").
    r.expect(authData.prefix(32).hexString, rpIdHashGolden, "authenticatorData rpIdHash == SHA256(example.com)")

    // Flags byte at offset 32 has UP and UV set.
    r.expect(authData[authData.startIndex + 32], 0x05, "authenticatorData flags byte == 0x05 (UP|UV)")

    // signCount big-endian 4 bytes == 0.
    r.expect(authData.suffix(4).hexString, "00000000", "authenticatorData signCount 0 big-endian")

    // Non-zero signCount big-endian encoding.
    let ad2 = Fido2Authenticator.authenticatorData(rpId: "example.com", flags: [.userPresent], signCount: 0x01020304)
    r.expect(ad2.suffix(4).hexString, "01020304", "authenticatorData signCount big-endian encoding")
    r.expect(ad2[ad2.startIndex + 32], 0x01, "authenticatorData flags byte == 0x01 (UP only)")
}

func checkAssertion(_ r: inout TestRunner) {
    let key = CredentialKey()
    let clientDataHash = Data((0..<32).map { UInt8($0) })

    do {
        let (authData, signature) = try Fido2Authenticator.assert(
            rpId: "example.com",
            clientDataHash: clientDataHash,
            signCount: 7,
            userVerified: true,
            key: key
        )

        // authData structure: UP|UV flags, signCount 7 big-endian.
        r.expect(authData.count, 37, "assert authData is 37 bytes")
        r.expect(authData[authData.startIndex + 32], 0x05, "assert flags has UP and UV")
        r.expect(authData.suffix(4).hexString, "00000007", "assert signCount 7 big-endian")

        // Sign-then-verify round-trip: signature must be valid (DER) over (authData || clientDataHash).
        let ecdsa = try P256.Signing.ECDSASignature(derRepresentation: signature)
        let valid = key.publicKey.isValidSignature(ecdsa, for: authData + clientDataHash)
        r.expectTrue(valid, "assert signature verifies over authData || clientDataHash (DER)")

        // Wrong message should NOT verify.
        let wrong = key.publicKey.isValidSignature(ecdsa, for: authData + Data(repeating: 0xff, count: 32))
        r.expectTrue(!wrong, "assert signature does not verify over wrong message")
    } catch {
        r.expectTrue(false, "assert threw: \(error)")
    }

    // userVerified: false -> flags only UP.
    do {
        let (authData, _) = try Fido2Authenticator.assert(
            rpId: "example.com",
            clientDataHash: clientDataHash,
            signCount: 0,
            userVerified: false,
            key: key
        )
        r.expect(authData[authData.startIndex + 32], 0x01, "assert userVerified=false -> flags 0x01 (UP only)")
    } catch {
        r.expectTrue(false, "assert (uv=false) threw: \(error)")
    }
}
